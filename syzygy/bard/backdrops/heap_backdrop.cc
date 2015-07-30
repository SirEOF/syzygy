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

#include "syzygy/bard/backdrops/heap_backdrop.h"

#include "base/logging.h"

namespace bard {
namespace backdrops {

HeapBackdrop::HeapBackdrop() {
}

void HeapBackdrop::UpdateStats(std::string name, uint64 time) {
  base::AutoLock auto_lock(lock_);

  auto stats = total_stats_.insert(std::make_pair(name, struct Stats())).first;
  stats->second.calls++;
  stats->second.time += time;
}

}  // namespace backdrops
}  // namespace bard