// Axel '0vercl0k' Souchet 5 Feb 2017
#include "syzygy/instrument/instrumenters/afl_instrumenter.h"

#include "base/logging.h"
#include "syzygy/application/application.h"
#include "syzygy/pe/image_filter.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/application/application.h"

#include "base/values.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"

namespace instrument {
namespace instrumenters {

bool AFLInstrumenter::ReadFromJSON(const std::string& json) {
  std::unique_ptr<base::Value> value(
    base::JSONReader::Read(json).release()
  );

  if (value.get() == nullptr) {
    LOG(ERROR) << "Invalid or empty JSON configuration.";
    return false;
  }

  if (!value->IsType(base::Value::TYPE_DICTIONARY)) {
    LOG(ERROR) << "Invalid JSON configuration.";
    return false;
  }

  const base::DictionaryValue* outer_dict =
    reinterpret_cast<const base::DictionaryValue*>(value.get());

  const base::ListValue *instrument_list = nullptr,
                        *dontinstrument_list = nullptr,
                        *to_parse_list = nullptr;

  outer_dict->GetList("instrument", &instrument_list);
  outer_dict->GetList("dontinstrument", &dontinstrument_list);

  if (instrument_list == nullptr && dontinstrument_list == nullptr) {
    LOG(ERROR) << "JSON file must contain either 'instrument' or 'dontinstrument'.";
    return false;
  }

  if (instrument_list != nullptr && dontinstrument_list != nullptr) {
    LOG(ERROR) << "'instrument' and 'dontinstrument' are mutally exclusive.";
    return false;
  }

  whitelist_mode_ = instrument_list != nullptr;
  if (whitelist_mode_) {
    to_parse_list = instrument_list;
  } else {
    to_parse_list = dontinstrument_list;
  }

  base::ListValue::const_iterator list_iter = to_parse_list->begin();
  for (; list_iter != to_parse_list->end(); ++list_iter) {
    std::string fname;
    if (!(*list_iter)->GetAsString(&fname)) {
      LOG(ERROR) << "'instrument' or 'dontinstrument' must be composed of strings only.";
      continue;
    }

    target_set_.insert(fname);
  }

  return true;
}

bool AFLInstrumenter::ReadFromJSONPath(const base::FilePath& path) {
  std::string file_string;
  if (!base::ReadFileToString(path, &file_string)) {
    LOG(ERROR) << "Unable to read file to string.";
    return false;
  }

  if (!ReadFromJSON(file_string)) {
    LOG(ERROR) << "Unable to parse JSON string.";
    return false;
  }

  return true;
}

bool AFLInstrumenter::DoCommandLineParse(const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  // Parse the config path parameter (optional).
  if (command_line->HasSwitch("config")) {
    base::FilePath config_path = application::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("config")
    );

    if (!ReadFromJSONPath(config_path)) {
      LOG(ERROR) << "Unable to parse JSON file.";
      return false;
    }
  }

  // Parse the force decomposition flag (optional).
  force_decomposition_ = command_line->HasSwitch("force-decompose");
  if (force_decomposition_) {
    LOG(INFO) << "Force decomposition mode enabled.";
  }

  // Parse the multithread flag (optional).
  multithread_mode_ = command_line->HasSwitch("multithread");
  if (multithread_mode_) {
    LOG(INFO) << "Thread-safe instrumentation mode enabled.";
  }

  // Parse the cookie check hook flag (optional).
  cookie_check_hook_ = command_line->HasSwitch("cookie-check-hook");
  if (cookie_check_hook_) {
    LOG(INFO) << "__security_cookie_check hook mode enabled.";
  }

  return true;
}

bool AFLInstrumenter::InstrumentPrepare() {
  return true;
}

bool AFLInstrumenter::InstrumentImpl() {
  transformer_.reset(
    new instrument::transforms::AFLTransform(
      target_set_, whitelist_mode_,
      force_decomposition_, multithread_mode_,
      cookie_check_hook_
    )
  );

  if (!relinker_->AppendTransform(transformer_.get())) {
    LOG(ERROR) << "AppendTransform failed.";
    return false;
  }

  add_bb_addr_stream_mutator_.reset(new
    instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
      transformer_->bb_ranges(),
      common::kBasicBlockRangesStreamName
    )
  );

  if (!relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get())) {
    LOG(ERROR) << "AppendPdbMutator failed.";
    return false;
  }

  return true;
}

const char *AFLInstrumenter::InstrumentationMode() {
  return "afl";
}

}
}
