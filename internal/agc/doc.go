// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package agc is a custom gargabe gollector for TinyGo. The main difference is instead of taking
// ownership of the entire process heap, it uses malloc to allocate blocks for the GC to then
// assign to allocated objects.
//
// Unfortunately, we must rely on a package init() method for initializing the heap because we
// cannot override TinyGo's initHeap function that normally does it. This means initialization
// order matters, this package should be the first package to be initialized - any packages
// initialized before cannot allocate memory. For that reason, we have named this agc instead
// of gc.
//
// Currently, only one block can be allocated meaning this has a fixed-size heap.
package agc
