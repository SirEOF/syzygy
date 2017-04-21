// Axel '0vercl0k' Souchet 1 April 2017
#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"

#include "syzygy/pe/pe_utils.h"
#include "syzygy/block_graph/typed_block.h"

#include <windows.h>

namespace instrument {
namespace transforms {

using block_graph::TypedBlock;

const char AddImplicitTlsTransform::kTransformName[] = "AddImplicitTlsTransform";

#pragma pack(push, 1)

// Describe the layout of the .tls section when using the MultiThread mode
typedef struct {
  uint32_t __tls_start;
  uint32_t __afl_prev_loc_tls;
  uint8_t __tls_end;
} DOT_TLS_SECTION_CONTENT;

#pragma pack(pop)

bool AddImplicitTlsTransform::TransformBlockGraph(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BlockGraph::Block* header_block
) {
  const BlockGraph::BlockMap &blocks = block_graph->blocks();
  BlockGraph::Block *_tls_index = nullptr;

  for (const auto &block : blocks) {
    std::string name(block.second.name());
    if (name == "_tls_index") {
      _tls_index = block_graph->GetBlockById(block.first);
      break;
    }
  }

  if (_tls_index == nullptr) {
    // If we don't have an existing implicit TLS slot, we need to inject the metadata in the
    // PE to add one
    return CreateImplicitTlsSlot(block_graph, header_block);
  } else {
    // If we do, we have at least one TLS slot defined, so we will just insert / add ours
    return InsertImplicitTlsSlot(block_graph);
  }
}

bool AddImplicitTlsTransform::CreateImplicitTlsSlot(
  BlockGraph* block_graph,
  BlockGraph::Block* header_block
) {
  /// "Thread Local Storage, part 3: Compiler and linker support for implicit TLS"
  /// http://www.nynaeve.net/?p=183
  LOG(INFO) << "Your binary does not have any implicit TLS, so we will inject some in the binary..";

  // This is the section where we will place the TLS slot for __afl_prev_loc.
  // Note that, this variable will never get referenced - it is used just by the compiler to know at what offset
  // from the implicit TLS memory this variable is. It is also used for the loader to know what size it has to
  // allocate for the implicit TLS (__tls_end - __tls_start), cf link above
  BlockGraph::Section* section_tls = block_graph->FindOrAddSection(
    // Only having a variable declared as 'declspec(__thread) foo;' but
    // not used ends up adding it into the .tls section, but no _tls_index/used variable is present in the binary.
    // As we assume the section is empty, and that our metadata is at the begining of the section we would have
    // to account for any data that is there before (think: [foo / __tls_start / slot / __tls_end]; in the current
    // code `slot` would be at displacement +4 when it should be sizeof(foo) + 4.
    // So we create a whole new section for not getting into this issue
    ".mtls",
    pe::kReadWriteDataCharacteristics
  );

  BlockGraph::Block *__tls_content = block_graph->AddBlock(
    BlockGraph::DATA_BLOCK,
    sizeof(DOT_TLS_SECTION_CONTENT),
    "__tls_content"
  );

  __tls_content->set_section(section_tls->id());

  // In the rdata section we inject the IMAGE_TLS_DIRECTORY metadata information. This is the glue that links
  // everything together - and obviously the metadata that the PE loader consults to allocate properly the
  // memory for the module's implicit TLS slots
  BlockGraph::Section* section_rdata = block_graph->FindOrAddSection(
    pe::kReadOnlyDataSectionName,
    pe::kReadOnlyDataCharacteristics
  );

  BlockGraph::Block *___xl_z = block_graph->AddBlock(
    BlockGraph::DATA_BLOCK,
    sizeof(uint32_t),
    "___xl_z"
  );

  BlockGraph::Block *__tls_used = block_graph->AddBlock(
    BlockGraph::DATA_BLOCK,
    sizeof(IMAGE_TLS_DIRECTORY),
    "__tls_used"
  );

  __tls_used->SetReference(
    offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData),
    BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF,
      BlockGraph::Reference::kMaximumSize,
      __tls_content,
      offsetof(DOT_TLS_SECTION_CONTENT, __tls_start),
      0
    )
  );

  __tls_used->SetReference(
    offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData),
    BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF,
      BlockGraph::Reference::kMaximumSize,
      __tls_content,
      offsetof(DOT_TLS_SECTION_CONTENT, __tls_end),
      0
    )
  );

  // We use the __tls_index variable in the .afl section. This variable gets updated by the loader,
  // (during the mapping of the PE) with a per-module index.
  // Then each thread indexes into the TEB.ThreadLocalStoragePointer array with this index, and will find
  // a base pointer into a memory location where the TLS slots are living
  __tls_used->SetReference(
    offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex),
    BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF,
      BlockGraph::Reference::kMaximumSize,
      afl_static_cov_data_,
      tls_index_offset_,
      0
    )
  );

  __tls_used->SetReference(
    offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks),
    BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF,
      BlockGraph::Reference::kMaximumSize,
      ___xl_z,
      0,
      0
    )
  );

  PIMAGE_TLS_DIRECTORY tls_dir = PIMAGE_TLS_DIRECTORY(
    __tls_used->AllocateData(__tls_used->size())
  );
  tls_dir->SizeOfZeroFill = 0;
  tls_dir->Characteristics = IMAGE_SCN_ALIGN_4BYTES;

  __tls_used->set_section(section_rdata->id());
  ___xl_z->set_section(section_rdata->id());

  // We know that __afl_prev_loc has been placed at the offset +4 in the .tls section - the instrumentation part
  // uses this displacement to properly index into the memory that the loader allocates
  tls_displacement_ = 4;

  TypedBlock<IMAGE_DOS_HEADER> dos_header;
  TypedBlock<IMAGE_NT_HEADERS> nt_headers;

  if (!dos_header.Init(0, header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to dereference NT headers.";
    return false;
  }

  IMAGE_DATA_DIRECTORY& tls_dir_info =
    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

  tls_dir_info.VirtualAddress = 0;
  tls_dir_info.Size = sizeof(IMAGE_TLS_DIRECTORY);
  // Link the TLS Directory RVA to the __tls_used block
  nt_headers.SetReference(
    BlockGraph::RELATIVE_REF,
    tls_dir_info.VirtualAddress,
    __tls_used, 0, 0
  );

  return true;
}

bool AddImplicitTlsTransform::InsertImplicitTlsSlot(
  BlockGraph* block_graph
) {
  LOG(INFO) << "Your binary has implicit TLS defined, appending __afl_prev_loc..";
  const BlockGraph::BlockMap &blocks = block_graph->blocks();
  BlockGraph::Block *__tls_used = nullptr;

  for (auto it = blocks.begin(); it != blocks.end(); ++it) {
    std::string name(it->second.name());
    if (name == "_tls_used") {
      __tls_used = block_graph->GetBlockById(it->first);
      break;
    }
  }

  if (__tls_used == nullptr) {
    LOG(ERROR) << "Could not find __tls_used.";
    return false;
  }

  BlockGraph::Reference __tls_start_ref, __tls_index_ref;
  if (!__tls_used->GetReference(offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData), &__tls_start_ref)) {
    LOG(ERROR) << "Could not get a reference onto __tls_start.";
    return false;
  }

  if (!__tls_used->GetReference(offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex), &__tls_index_ref)) {
    LOG(ERROR) << "Could not get a reference onto __tls_index.";
    return false;
  }

  BlockGraph::Block *__tls_start = __tls_start_ref.referenced();
  size_t size_block = __tls_start->size();
  if ((size_block % 4) != 0) {
    // Align up to the next uint32_t. What usually happens is that tls_end is 1 byte long, so you end up
    // with an unaligned number - aligning it here to simplify the arithmetic
    size_block += 4 - (size_block % 4);
  }

  size_t n_slots = (size_block - (sizeof(uint32_t) * 2)) / sizeof(uint32_t); // sizeof(__tls_start) + sizeof(__tls_end)
  size_t slot_offset = (n_slots + 1) * sizeof(uint32_t);
  if (size_block == 4) {
    // We can end up with __tls_start followed by __tls_end - when no TLS slot is defined,
    // but TLS metadata is still present in the binary (for the callbacks usage for example).
    // If this happen, we make sure to set n_slots to 0
    n_slots = 0;
    // The slot_offset is used to go and insert data right *after* __tls_start (this will be our TLS slot).
    // The way InsertData works is that it takes the data from offset X and shifts it by the size of data we want to insert.
    // In order to insert data *after* __tls_start and keep the following layout:
    // [__tls_start / __afl_prev_loc_tls / __tls_end]
    // We need to use an offset set to 1.
    // If the offset is 0, it means both __tls_start and __tls_end get shifted + 4 bytes forward like this:
    // [ __afl_prev_loc_tls / __tls_start / __tls_end
    slot_offset = 1;
    VLOG(1) << "The binary did not have any already defined slot, so inserting space between __tls_start and __tls_end";
  } else {
    VLOG(1) << "The binary has already " << n_slots << " implicit TLS slots";
  }

  // Adding 4 new bytes for __afl_prev_loc_tls
  __tls_start->InsertData(slot_offset, sizeof(uint32_t), true);
  __tls_start->SetLabel(slot_offset, "__afl_prev_loc_tls", BlockGraph::DATA_LABEL);
  tls_displacement_ = slot_offset;

  // Now we need to remove the "old" __tls_index and transfers it to the one in the .afl section
  BlockGraph::Block *__old_tls_index = __tls_index_ref.referenced();
  __old_tls_index->TransferReferrers(
    tls_index_offset_,
    afl_static_cov_data_,
    BlockGraph::Block::kTransferInternalReferences
  );

  __old_tls_index->RemoveAllReferences();
  if (!block_graph->RemoveBlock(__old_tls_index)) {
    LOG(ERROR) << "Removing the __old_tls_index failed.";
    return false;
  }

  return true;
}

}
}
