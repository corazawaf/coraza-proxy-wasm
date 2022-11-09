// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package agc is a custom garbage collector for TinyGo. It delegates to bdwgc for actual
// allocation and collection.
//
// Unfortunately, we must rely on a package init() method for initializing the heap because we
// cannot override TinyGo's initHeap function that normally does it. This means initialization
// order matters, this package should be the first package to be initialized - any packages
// initialized before cannot allocate memory. For that reason, we have named this agc instead
// of gc.
package agc
