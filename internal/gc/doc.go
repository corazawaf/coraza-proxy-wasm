// Package gc is a custom gargabe gollector for TinyGo. The main difference is instead of taking
// ownership of the entire process heap, it uses malloc to allocate blocks for the GC to then
// assign to allocated objects.
//
// Currently, only one block can be allocated meaning this has a fixed-size heap.
package gc
