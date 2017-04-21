// Axel '0vercl0k' Souchet 5 Feb 2017
#ifndef SYZYGY_INSTRUMENTERS_AFL_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENTERS_AFL_INSTRUMENTER_H_

#include <string>
#include <unordered_set>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"
#include "syzygy/instrument/transforms/afl_transform.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class AFLInstrumenter : public InstrumenterWithRelinker {
public:
  typedef InstrumenterWithRelinker Super;

  AFLInstrumenter()
  : Super()
  { }

  ~AFLInstrumenter()
  { }


  bool ReadFromJSON(const std::string& json);
  bool ReadFromJSONPath(const base::FilePath& path);

  // From InstrumenterWithRelinker
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override;
  bool DoCommandLineParse(const base::CommandLine* command_line) override;

protected:

  // Force decomposition flag
  bool force_decomposition_;

  // Thread-safe instrumentation flag (with __afl_prev_loc stored in TLS)
  bool multithread_mode_;

  // Stores the whitelist / blacklist of functions to instrument / or not
  std::unordered_set<std::string> target_set_;
  bool whitelist_mode_;

  // Path to the JSON describing the instrumentation properties
  base::FilePath config_path_;

  // Cookie check hook flag (redirect __security_cookie_check to a custom stub)
  bool cookie_check_hook_;

  // The transform for this agent.
  std::unique_ptr<instrument::transforms::AFLTransform>
      transformer_;

  // The PDB mutator for this agent.
  std::unique_ptr<instrument::mutators::AddIndexedDataRangesStreamPdbMutator>
      add_bb_addr_stream_mutator_;

  DISALLOW_COPY_AND_ASSIGN(AFLInstrumenter);
};

}  // namespace instrumenters
}  // namespace instrument

#endif
