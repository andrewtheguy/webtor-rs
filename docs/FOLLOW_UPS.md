# Follow-ups

Known places where a responsibility sits in the wrong module. None of them is
a bug: each is work that would make a boundary honest, written down so the
reasoning does not have to be rediscovered. Delete an entry when it is done —
the commit history is the record that it was.

The two that used to head this list are done: the caller can now read a
directory seed with `describeDirectory` instead of parsing a consensus itself,
and it can take webtor's log lines with `onLog` instead of getting the console
whether it wants it or not.

## `directory.rs` is four responsibilities in one module

It holds the HTTP-over-directory-stream transport (`fetch_directory_document`,
`post_directory_document`, the status parsing and the deflate decoding), the
seed envelope's codec, consensus validation, and relay selection. The tell is
that `onion_service.rs` imports `post_directory_document` from it to upload a
descriptor: descriptor publication reaching into the directory manager for
HTTP plumbing. A `dir_http.rs` holding the request/response shapes both callers
need would leave `directory.rs` with the directory itself.

## `DirectoryManager::relay_manager` is a public field

It is public so `client.rs` can pass the same `RelayManager` to the onion
connector and to a published service. That makes internal state part of the
type's surface for a reason that an accessor, or handing the manager out at
construction, would cover.

## A refreshed directory is never offered to the caller

A published service refreshes the directory and republishes every 60–120
minutes (`onion_service.rs`), but `directoryCache()` is pull-only: a caller
that exports the cache once after `create` — the obvious thing to do, and what
the callers here do — persists the bootstrap directory and never sees a
refreshed one. An `onDirectoryChange` callback would close that without webtor
learning anything about how the caller stores it.

## The examples each carry their own copy of the seed store

`examples/nostr-onion-poc/src/directory-cache.ts` and
`examples/onion-service-poc/src/directory-cache.ts` are identical. They are
example code and each example is meant to read on its own, so this is cosmetic
— but a reader comparing the two learns nothing from the second copy.
