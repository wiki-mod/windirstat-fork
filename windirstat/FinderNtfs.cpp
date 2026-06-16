// WinDirStat - Directory Statistics
// Copyright © WinDirStat Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#include "pch.h"
#include "FinderNtfs.h"

enum ATTRIBUTE_TYPE_CODE : ULONG
{
    AttributeStandardInformation = 0x10,
    AttributeFileName = 0x30,
    AttributeData = 0x80,
    AttributeReparsePoint = 0xC0,
    AttributeEnd = 0xFFFFFFFF,
};

using FILE_RECORD = struct FILE_RECORD
{
    ULONG Signature;
    USHORT UsaOffset;
    USHORT UsaCount;
    ULONGLONG Lsn;
    USHORT SequenceNumber;
    USHORT LinkCount;
    USHORT FirstAttributeOffset;
    USHORT Flags;
    ULONG FirstFreeByte;
    ULONG BytesAvailable;
    ULONGLONG BaseFileRecordNumber : 48;
    ULONGLONG BaseFileRecordSequence : 16;
    USHORT NextAttributeNumber;
    USHORT SegmentNumberHighPart;
    ULONG SegmentNumberLowPart;

    constexpr ULONGLONG SegmentNumber() const noexcept
    {
        return static_cast<ULONGLONG>(SegmentNumberHighPart) << 32ul | SegmentNumberLowPart;
    }

    constexpr bool IsValid() const noexcept
    {
        return Signature == 0x454C4946; // 'FILE'
    }
    constexpr bool IsInUse() const noexcept
    {
        return Flags & 0x0001;
    }

    constexpr bool IsDirectory() const noexcept
    {
        return Flags & 0x0002;
    }
};

using ATTRIBUTE_RECORD = struct ATTRIBUTE_RECORD
{
    ATTRIBUTE_TYPE_CODE TypeCode;
    ULONG RecordLength;
    UCHAR FormCode;
    UCHAR NameLength;
    USHORT NameOffset;
    USHORT Flags;
    USHORT Instance;

    union
    {
        struct
        {
            ULONG ValueLength;
            USHORT ValueOffset;
            UCHAR Reserved[2];
        } Resident;

        struct
        {
            LONGLONG LowestVcn;
            LONGLONG HighestVcn;
            USHORT DataRunOffset;
            USHORT CompressionSize;
            UCHAR Padding[4];
            ULONGLONG AllocatedLength;
            ULONGLONG FileSize;
            ULONGLONG ValidDataLength;
            ULONGLONG Compressed;
        } Nonresident;
    } Form;

    constexpr bool IsNonResident() const noexcept
    {
        return FormCode & 0x0001;
    }

    constexpr bool IsCompressed() const noexcept
    {
        return Flags & 0x0001;
    }

    constexpr bool IsSparse() const noexcept
    {
        return Flags & 0x8000;
    }

    ATTRIBUTE_RECORD* next() const noexcept
    {
        return ByteOffset<ATTRIBUTE_RECORD>(const_cast<ATTRIBUTE_RECORD*>(this), RecordLength);
    }

    static constexpr std::pair<ATTRIBUTE_RECORD*, ATTRIBUTE_RECORD*> bounds(FILE_RECORD* FileRecord, auto TotalLength) noexcept
    {
        return {
            ByteOffset<ATTRIBUTE_RECORD>(FileRecord, FileRecord->FirstAttributeOffset),
            ByteOffset<ATTRIBUTE_RECORD>(FileRecord, TotalLength)
        };
    }
};

using FILE_NAME = struct FILE_NAME
{
    ULONGLONG ParentDirectory : 48;
    ULONGLONG ParentSequence : 16;
    LONGLONG CreationTime;
    LONGLONG LastModificationTime;
    LONGLONG MftChangeTime;
    LONGLONG LastAccessTime;
    LONGLONG AllocatedLength;
    LONGLONG FileSize;
    ULONG FileAttributes;
    USHORT PackedEaSize;
    USHORT Reserved;
    UCHAR FileNameLength;
    UCHAR Flags;
    WCHAR FileName[1];

    constexpr bool IsShortNameRecord() const noexcept
    {
        return Flags == 0x02;
    }
};

using STANDARD_INFORMATION = struct STANDARD_INFORMATION
{
    FILETIME CreationTime;
    FILETIME LastModificationTime;
    FILETIME MftChangeTime;
    FILETIME LastAccessTime;
    ULONG FileAttributes;
};

bool FinderNtfsContext::LoadRoot(CItem* driveitem)
{
    // Trim off excess characters
    std::wstring volumePath = driveitem->GetPathLong();
    while (!volumePath.empty() && volumePath.back() == L'\\') volumePath.pop_back();
    if (!volumePath.empty() && volumePath[0] != L'\\' && volumePath[0] != L'/') volumePath.insert(0, L"\\\\.\\");

    // Open volume handle with FILE_FLAG_OVERLAPPED for asynchronous I/O
    SmartPointer volumeHandle(CloseHandle, CreateFile(volumePath.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, nullptr));
    if (volumeHandle == INVALID_HANDLE_VALUE) return false;

    // Get volume information
    NTFS_VOLUME_DATA_BUFFER volumeInfo = {};
    ULONG bytesReturned;
    if (!DeviceIoControl(volumeHandle, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0, &volumeInfo, sizeof(volumeInfo), &bytesReturned, nullptr)) return
        false;

    // Get MFT retrieval pointers
    SmartPointer fileHandle(CloseHandle, CreateFile((volumePath + L"\\$MFT::$DATA").c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_NO_BUFFERING, nullptr));
    if (fileHandle == INVALID_HANDLE_VALUE) return false;

    std::vector<BYTE> dataRunsBuffer(sizeof(RETRIEVAL_POINTERS_BUFFER) + 32 * sizeof(LARGE_INTEGER));
    STARTING_VCN_INPUT_BUFFER input = {};
    BOOL pointersFetched = FALSE;
    while ((pointersFetched = DeviceIoControl(fileHandle, FSCTL_GET_RETRIEVAL_POINTERS, &input, sizeof(input), dataRunsBuffer.data(),
        static_cast<DWORD>(dataRunsBuffer.size()), &bytesReturned, nullptr)) == FALSE && GetLastError() == ERROR_MORE_DATA)
    {
        dataRunsBuffer.resize(dataRunsBuffer.size() * 2);
    }
    if (pointersFetched == FALSE)
    {
        return false;
    }

    // Extract data run origins and cluster counts
    RETRIEVAL_POINTERS_BUFFER* retrievalBuffer = ByteOffset<RETRIEVAL_POINTERS_BUFFER>(dataRunsBuffer.data(), 0);
    std::vector<std::tuple<ULONGLONG, LONGLONG, ULONGLONG>> dataRuns(retrievalBuffer->ExtentCount, {});
    auto vcnStart = retrievalBuffer->StartingVcn.QuadPart;
    for (const auto i : std::views::iota(0u, retrievalBuffer->ExtentCount))
    {
        const auto vcnNext = retrievalBuffer->Extents[i].NextVcn.QuadPart;
        dataRuns[i] = std::make_tuple(
            static_cast<ULONGLONG>(vcnStart),
            retrievalBuffer->Extents[i].Lcn.QuadPart,
            static_cast<ULONGLONG>(vcnNext - vcnStart)
        );
        vcnStart = vcnNext;
    }

    // Pre-reserve hash maps to eliminate rehashing on large volumes.
    // MftValidDataLength / BytesPerFileRecordSegment estimates the number of live records.
    if (volumeInfo.BytesPerFileRecordSegment > 0)
    {
        const ULONGLONG estimated = volumeInfo.MftValidDataLength.QuadPart / volumeInfo.BytesPerFileRecordSegment;
        m_baseFileRecordMap.reserve(estimated * 4 / 3);
        m_parentToChildMap.reserve(estimated / 6);
    }

    // Build a flat list of equal-sized I/O chunks covering every data run.
    // 16 MiB per chunk reduces syscall overhead on NVMe vs the old 4 MiB.
    constexpr ULONGLONG kChunkBytes   = 16ull * wds::Mi;
    constexpr size_t    kBufAlignment = 4ull  * wds::Ki;

    struct ReadChunk { ULONGLONG byteOffset; ULONGLONG byteCount; };
    std::vector<ReadChunk> allChunks;
    for (const auto& [vcnStart, lcn, clusterCount] : dataRuns)
    {
        const ULONGLONG base  = static_cast<ULONGLONG>(lcn) * volumeInfo.BytesPerCluster;
        const ULONGLONG total = clusterCount * volumeInfo.BytesPerCluster;
        for (ULONGLONG off = 0; off < total; off += kChunkBytes)
            allChunks.push_back({base + off, std::min(kChunkBytes, total - off)});
    }

    // Per-thread staging: parse into thread-local vectors with no locks, then
    // do a single-threaded merge into the shared maps (which are pre-reserved).
    struct ChildRecord  { ULONGLONG parentId; FileRecordName name; };
    struct ThreadStaging
    {
        std::vector<std::pair<ULONGLONG, FileRecordBase>> baseRecords;
        std::vector<ChildRecord>                          children;
    };

    // Cap at 8 workers: each needs a 16 MiB buffer; beyond 8 the I/O queue
    // depth of the drive is the bottleneck, not thread count.
    const size_t numWorkers = std::clamp(
        static_cast<size_t>(std::thread::hardware_concurrency()), size_t{1}, std::min(size_t{8}, allChunks.size()));
    std::vector<ThreadStaging> staging(numWorkers);
    std::atomic<size_t>        nextChunk{0};

    auto workerFn = [&](const size_t workerIdx)
    {
        auto& local = staging[workerIdx];

        // Each worker opens its own handle so reads can be issued in parallel.
        SmartPointer localHandle(CloseHandle, CreateFile(volumePath.c_str(),
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, nullptr));
        if (localHandle == INVALID_HANDLE_VALUE) return;

        std::unique_ptr<UCHAR, decltype(&_aligned_free)> buffer(
            static_cast<UCHAR*>(_aligned_malloc(kChunkBytes, kBufAlignment)), &_aligned_free);
        if (!buffer) return;
        SmartPointer event(CloseHandle, CreateEvent(nullptr, FALSE, FALSE, nullptr));
        if (event == nullptr) return;

        while (true)
        {
            const size_t ci = nextChunk.fetch_add(1, std::memory_order_relaxed);
            if (ci >= allChunks.size()) break;

            driveitem->UpwardDrivePacman();

            const auto& [byteOffset, byteCount] = allChunks[ci];
            ULONG bytesRead = 0;
            OVERLAPPED ov = {
                .Offset     = static_cast<DWORD>(byteOffset & 0xFFFF'FFFFu),
                .OffsetHigh = static_cast<DWORD>(byteOffset >> 32),
                .hEvent     = event
            };
            if (ReadFile(localHandle, buffer.get(), static_cast<ULONG>(byteCount), &bytesRead, &ov) == 0)
            {
                if (GetLastError() != ERROR_IO_PENDING ||
                    WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0 ||
                    GetOverlappedResult(localHandle, &ov, &bytesRead, FALSE) == 0)
                {
                    VTRACE(L"ERROR: Failed to read MFT chunk.");
                    continue;
                }
            }

            for (ULONG offset = 0; offset + volumeInfo.BytesPerFileRecordSegment <= bytesRead;
                 offset += volumeInfo.BytesPerFileRecordSegment)
            {
                const auto fileRecord = ByteOffset<FILE_RECORD>(buffer.get(), offset);

                if (fileRecord->UsaOffset + sizeof(USHORT) * fileRecord->UsaCount > volumeInfo.BytesPerFileRecordSegment) continue;
                if (fileRecord->FirstAttributeOffset >= volumeInfo.BytesPerFileRecordSegment) continue;

                // Apply fixup (NTFS MFT records always use 512-byte sector size)
                constexpr auto kMftSectorSize  = 512u;
                constexpr auto kWordsPerSector = kMftSectorSize / sizeof(USHORT);
                const auto  fixupArray = ByteOffset<USHORT>(fileRecord, fileRecord->UsaOffset);
                const USHORT usn       = fixupArray[0];
                const auto   recWords  = reinterpret_cast<PUSHORT>(ByteOffset<UCHAR>(buffer.get(), offset));
                bool skipRecord = false;
                if (fileRecord->UsaCount > 0) for (const auto i : std::views::iota(1u, fileRecord->UsaCount))
                {
                    const auto sectorEnd = recWords + i * kWordsPerSector - 1;
                    if (*sectorEnd == usn) *sectorEnd = fixupArray[i];
                    else { skipRecord = true; break; }
                }
                if (skipRecord) [[unlikely]] continue;

                if (!fileRecord->IsValid() || !fileRecord->IsInUse()) continue;

                const ULONGLONG currentRecord  = fileRecord->SegmentNumber();
                const ULONGLONG baseRecordIndex = fileRecord->BaseFileRecordNumber > 0 ? fileRecord->BaseFileRecordNumber : currentRecord;

                // Accumulate attributes for this record into a stack-local struct —
                // no shared-map access during parsing, so no lock needed.
                FileRecordBase localBase{};

                for (auto [cur, end] = ATTRIBUTE_RECORD::bounds(fileRecord, volumeInfo.BytesPerFileRecordSegment);
                     cur < end && cur->TypeCode != AttributeEnd && cur->RecordLength > 0;
                     cur = cur->next())
                {
                    if (cur->TypeCode == AttributeStandardInformation)
                    {
                        if (cur->IsNonResident()) continue;
                        const auto si = ByteOffset<STANDARD_INFORMATION>(cur, cur->Form.Resident.ValueOffset);
                        localBase.LastModifiedTime = si->LastModificationTime;
                        localBase.Attributes       = si->FileAttributes;
                        if (fileRecord->IsDirectory()) localBase.Attributes |= FILE_ATTRIBUTE_DIRECTORY;
                        if (localBase.Attributes == 0) localBase.Attributes  = FILE_ATTRIBUTE_NORMAL;
                    }
                    else if (cur->TypeCode == AttributeFileName)
                    {
                        if (cur->IsNonResident()) continue;
                        const auto fn = ByteOffset<FILE_NAME>(cur, cur->Form.Resident.ValueOffset);
                        if (fn->IsShortNameRecord() ||
                            (fn->FileNameLength == 1 && fn->FileName[0] == L'.') ||
                            (fn->FileNameLength == 2 && fn->FileName[0] == L'.' && fn->FileName[1] == L'.')) continue;

                        local.children.push_back({fn->ParentDirectory,
                            FileRecordName{std::wstring{fn->FileName, fn->FileNameLength}, baseRecordIndex}});
                    }
                    else if (cur->TypeCode == AttributeData)
                    {
                        if (const WCHAR* streamName = ByteOffset<WCHAR>(cur, cur->NameOffset); cur->NameLength > 0)
                        {
                            if (std::wstring_view(streamName, cur->NameLength) == L"WofCompressedData" &&
                                (!cur->IsNonResident() || cur->Form.Nonresident.LowestVcn == 0))
                            {
                                localBase.PhysicalSize = cur->IsNonResident() ?
                                    cur->Form.Nonresident.AllocatedLength :
                                    (cur->Form.Resident.ValueLength + 7) & ~7;
                            }
                            continue;
                        }
                        if (cur->IsNonResident())
                        {
                            if (cur->Form.Nonresident.LowestVcn != 0) continue;
                            localBase.LogicalSize = cur->Form.Nonresident.FileSize;
                            if (const ULONGLONG phys = (cur->IsCompressed() || cur->IsSparse()) ?
                                cur->Form.Nonresident.Compressed : cur->Form.Nonresident.AllocatedLength; phys > 0)
                            {
                                localBase.PhysicalSize = phys;
                            }
                        }
                        else
                        {
                            localBase.LogicalSize  = cur->Form.Resident.ValueLength;
                            localBase.PhysicalSize = (cur->Form.Resident.ValueLength + 7) & ~7;
                        }
                    }
                    else if (cur->TypeCode == AttributeReparsePoint)
                    {
                        if (cur->IsNonResident()) continue;
                        const auto rp = ByteOffset<Finder::REPARSE_DATA_BUFFER>(cur, cur->Form.Resident.ValueOffset);
                        localBase.ReparsePointTag = rp->ReparseTag;
                        if (rp->ReparseTag == IO_REPARSE_TAG_WOF)
                            localBase.Attributes |= FILE_ATTRIBUTE_COMPRESSED;
                        if (Finder::IsJunction(*rp))
                            localBase.ReparsePointTag = IO_REPARSE_TAG_JUNCTION_POINT;
                    }
                }

                local.baseRecords.push_back({baseRecordIndex, localBase});
            }
        }
    };

    // Launch workers then join before touching the shared maps.
    std::vector<std::thread> workers;
    workers.reserve(numWorkers);
    for (size_t i = 0; i < numWorkers; i++)
        workers.emplace_back(workerFn, i);
    for (auto& w : workers) w.join();

    // Serial merge: O(N) with pre-reserved maps — no rehashing.
    // Attribute priority: $STANDARD_INFORMATION (Attributes != 0) wins for file
    // metadata; extension records only contribute $DATA sizes.
    for (auto& s : staging)
    {
        for (auto& [idx, rec] : s.baseRecords)
        {
            auto& dst = m_baseFileRecordMap[idx];
            if (rec.Attributes != 0)
            {
                dst.Attributes       = rec.Attributes;
                dst.LastModifiedTime = rec.LastModifiedTime;
            }
            if (rec.LogicalSize  > 0) dst.LogicalSize  = rec.LogicalSize;
            if (rec.PhysicalSize > 0) dst.PhysicalSize = rec.PhysicalSize;
            if (rec.ReparsePointTag != 0) dst.ReparsePointTag = rec.ReparsePointTag;
        }
        for (auto& entry : s.children)
            m_parentToChildMap[entry.parentId].emplace_back(std::move(entry.name));
    }

    // Verify root node exists
    if (!m_parentToChildMap.contains(NtfsNodeRoot))
    {
        return false;
    }

    driveitem->SetIndex(NtfsNodeRoot);
    m_isLoaded = true;
    return true;
}

bool FinderNtfs::FindNext()
{
    if (m_recordIterator == m_recordIteratorEnd) return false;
    m_index = m_recordIterator->BaseRecord;
    const auto it = m_master->m_baseFileRecordMap.find(m_index);
    if (it == m_master->m_baseFileRecordMap.end()) return false;
    m_currentRecord = &it->second;
    m_currentRecordName = &(*m_recordIterator);
    ++m_recordIterator;

    return true;
}

bool FinderNtfs::FindFile(const CItem* item)
{
    m_base = item->GetPath();
    const auto result = m_master->m_parentToChildMap.find(item->GetIndex());
    if (result == m_master->m_parentToChildMap.end()) return false;
    m_recordIteratorEnd = result->second.end();
    m_recordIterator = result->second.begin();
    return FindNext();
}

DWORD FinderNtfs::GetAttributes() const
{
    return m_currentRecord->Attributes;
}

ULONGLONG FinderNtfs::GetIndex() const
{
    return m_currentRecordName->BaseRecord;
}

DWORD FinderNtfs::GetReparseTag() const
{
    return m_currentRecord->ReparsePointTag;
}

std::wstring FinderNtfs::GetFileName() const
{
    return m_currentRecordName->FileName;
}

ULONGLONG FinderNtfs::GetFileSizePhysical() const
{
    return m_currentRecord->PhysicalSize;
}

ULONGLONG FinderNtfs::GetFileSizeLogical() const
{
    return m_currentRecord->LogicalSize;
}

FILETIME FinderNtfs::GetLastWriteTime() const
{
    return m_currentRecord->LastModifiedTime;
}

std::wstring FinderNtfs::GetFilePath() const
{
    // Get full path to folder or file
    std::wstring path = (m_base.back() == L'\\') ?
        (m_base + GetFileName()) :
        (m_base + L"\\" + GetFileName());

    // Strip special dos chars
    if (path.starts_with(s_dosUNCPath)) return L"\\\\" + path.substr(s_dosUNCPath.length());
    if (path.starts_with(s_dosPath)) return path.substr(s_dosPath.length());
    return path;
}

bool FinderNtfs::IsReserved() const
{
    return m_index < FinderNtfsContext::NtfsReservedMax;
}
