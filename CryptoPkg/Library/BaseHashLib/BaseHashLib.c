/** @file
  Unified Hash API Implementation

  This file implements the Unified Hash API.

  This API, when called, will calculate the Hash using the
  hashing algorithm specified by PcdSystemHashPolicy.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/BaseHashLib.h>

/**
  Init hash sequence.

  @param HashHandle  Hash handle.

  @retval TRUE       Hash start and HashHandle returned.
  @retval FALSE      Hash Init unsuccessful.
**/
BOOLEAN
EFIAPI
HashApiInit (
  OUT  HASH_HANDLE   *HashHandle
  )
{
  BOOLEAN  Status;
  VOID     *HashCtx;
  UINTN    CtxSize;

  switch (PcdGet8 (PcdSystemHashPolicy)) {
    case HASH_MD4:
      CtxSize = Md4GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Md4Init (HashCtx);
      break;

    case HASH_MD5:
      CtxSize = Md5GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

     Status = Md5Init (HashCtx);
      break;

    case HASH_SHA1:
      CtxSize = Sha1GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Sha1Init (HashCtx);
      break;

    case HASH_SHA256:
      CtxSize = Sha256GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Sha256Init (HashCtx);
      break;

    case HASH_SHA384:
      CtxSize = Sha384GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Sha384Init (HashCtx);
      break;

    case HASH_SHA512:
      CtxSize = Sha512GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Sha512Init (HashCtx);
      break;

    case HASH_SM3_256:
      CtxSize = Sm3GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      ASSERT (HashCtx != NULL);

      Status = Sm3Init (HashCtx);
      break;

    default:
      Status = FALSE;
      ASSERT (Status);
      break;
  }

  *HashHandle = (HASH_HANDLE)HashCtx;

  return Status;
}

/**
  Update hash data.

  @param HashHandle    Hash handle.
  @param DataToHash    Data to be hashed.
  @param DataToHashLen Data size.

  @retval TRUE         Hash updated.
  @retval FALSE        Hash updated unsuccessful.
**/
BOOLEAN
EFIAPI
HashApiUpdate (
  IN HASH_HANDLE    HashHandle,
  IN VOID           *DataToHash,
  IN UINTN          DataToHashLen
  )
{
  BOOLEAN  Status;
  VOID     *HashCtx;

  HashCtx = (VOID *)HashHandle;

  switch (PcdGet8 (PcdSystemHashPolicy)) {
    case HASH_MD4:
      Status = Md4Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_MD5:
      Status = Md5Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_SHA1:
      Status = Sha1Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_SHA256:
      Status = Sha256Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_SHA384:
      Status = Sha384Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_SHA512:
      Status = Sha512Update (HashCtx, DataToHash, DataToHashLen);
      break;

    case HASH_SM3_256:
      Status = Sm3Update (HashCtx, DataToHash, DataToHashLen);
      break;

    default:
      Status = FALSE;
      ASSERT (Status);
      break;
  }

  return Status;
}

/**
  Hash complete.

  @param HashHandle    Hash handle.
  @param Digest        Hash Digest.

  @retval TRUE         Hash complete and Digest is returned.
  @retval FALSE        Hash complete unsuccessful.
**/
BOOLEAN
EFIAPI
HashApiFinal (
  IN  HASH_HANDLE HashHandle,
  OUT UINT8      *Digest
  )
{
  BOOLEAN  Status;
  VOID     *HashCtx;

  HashCtx = (VOID *)HashHandle;

  switch (PcdGet8 (PcdSystemHashPolicy)) {
    case HASH_MD4:
      Status = Md4Final (HashCtx, Digest);
      break;

    case HASH_MD5:
      Status = Md5Final (HashCtx, Digest);
      break;

    case HASH_SHA1:
      Status = Sha1Final (HashCtx, Digest);
      break;

    case HASH_SHA256:
      Status = Sha256Final (HashCtx, Digest);
      break;

    case HASH_SHA384:
      Status = Sha384Final (HashCtx, Digest);
      break;

    case HASH_SHA512:
      Status = Sha512Final (HashCtx, Digest);
      break;

    case HASH_SM3_256:
      Status = Sm3Final (HashCtx, Digest);
      break;

    default:
      Status = FALSE;
      ASSERT (Status);
      break;
  }

  FreePool (HashCtx);

  return Status;
}
