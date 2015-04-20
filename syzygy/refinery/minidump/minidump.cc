// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "syzygy/refinery/minidump/minidump.h"

#include "base/file_util.h"
#include "base/logging.h"

namespace refinery {

Minidump::Minidump() {
}

Minidump::~Minidump() {
}

bool Minidump::Open(const base::FilePath& path) {
  file_.reset(base::OpenFile(path, "rb"));

  if (!file_)
    return false;

  // Read the header and validate the signature.
  MINIDUMP_HEADER header = {};
  if (!ReadBytes(0, sizeof(header), &header))
    return false;

  if (header.Signature != MINIDUMP_SIGNATURE ||
      header.NumberOfStreams == 0) {
    return false;
  }

  directory_.resize(header.NumberOfStreams);
  if (!ReadBytes(header.StreamDirectoryRva,
                 header.NumberOfStreams * sizeof(directory_[0]),
                 &directory_.at(0))) {
    return false;
  }

  return true;
}

Minidump::Stream Minidump::GetStreamFor(
    const MINIDUMP_LOCATION_DESCRIPTOR& location) {
  return Stream(this, location.Rva, location.DataSize, kNoStreamId);
}

Minidump::Stream Minidump::GetStream(size_t stream_id) {
  DCHECK_GT(directory_.size(), stream_id);
  const MINIDUMP_DIRECTORY& dir_entry = directory_[stream_id];

  return Stream(this,
                dir_entry.Location.Rva,
                dir_entry.Location.DataSize,
                stream_id);
}

Minidump::Stream Minidump::FindNextStream(const Stream* prev,
                                          size_t stream_type) {
  size_t start = prev ? prev->stream_id() + 1 : 0;

  for (size_t id = start; id < directory_.size(); ++id) {
    if (directory_[id].StreamType == stream_type)
      return GetStream(id);
  }

  // Not found, return an invalid stream.
  return Stream();
}

bool Minidump::ReadBytes(size_t offset, size_t data_size, void* data) {
  if (fseek(file_.get(), offset, SEEK_SET) != 0)
    return false;

  if (fread(data, 1, data_size, file_.get()) != data_size)
    return false;

  return true;
}

Minidump::Stream::Stream()
    : minidump_(nullptr),
      current_offset_(0),
      remaining_length_(0),
      stream_id_(0) {
}

Minidump::Stream::Stream(
    Minidump* minidump, size_t offset, size_t length, size_t stream_id)
        : minidump_(minidump),
          current_offset_(offset),
          remaining_length_(length),
          stream_id_(stream_id) {
  DCHECK_NE(static_cast<Minidump*>(nullptr), minidump);
}

bool Minidump::Stream::ReadBytes(size_t data_len, void* data) {
  if (data_len > remaining_length_)
    return false;

  if (!minidump_->ReadBytes(current_offset_, data_len, data))
    return false;

  current_offset_ += data_len;
  remaining_length_ -= data_len;

  return true;
}

}  // namespace refinery
