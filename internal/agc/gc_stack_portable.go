//go:build tinygo

package agc

import (
	"unsafe"
)

//go:extern runtime.stackChainStart
var stackChainStart *stackChainObject

type stackChainObject struct {
	parent   *stackChainObject
	numSlots uintptr
}

func addStackRoots() {
	stackObject := stackChainStart
	for stackObject != nil {
		start := uintptr(unsafe.Pointer(stackObject)) + unsafe.Sizeof(uintptr(0))*2
		end := start + stackObject.numSlots*unsafe.Alignof(uintptr(0))
		GC_add_roots(start, end)
		stackObject = stackObject.parent
	}
}

// markStack marks all root pointers found on the stack.
//
//   - Goroutine stacks are heap allocated and always reachable in some way
//     (for example through internal/task.currentTask) so they will always be
//     scanned.
//   - The system stack (aka startup stack) is not heap allocated, so even
//     though it may be referenced it will not be scanned by default.
//
// Therefore, we only need to scan the system stack.
// It is relatively easy to scan the system stack while we're on it: we can
// simply read __stack_pointer and __global_base and scan the area inbetween.
// Unfortunately, it's hard to get the system stack pointer while we're on a
// goroutine stack. But when we're on a goroutine stack, the system stack is in
// the scheduler which means there shouldn't be anything on the system stack
// anyway.
// ...I hope this assumption holds, otherwise we will need to store the system
// stack in a global or something.
//
// The compiler also inserts code to store all globals in a chain via
// stackChainStart. Luckily we don't need to scan these, as these globals are
// stored on the goroutine stack and are therefore already getting scanned.
func printStack() {
	stackObject := stackChainStart
	for stackObject != nil {
		println("stackChainStart", stackObject)
		stackObject = stackObject.parent
	}
}

// trackPointer is a stub function call inserted by the compiler during IR
// construction. Calls to it are later replaced with regular stack bookkeeping
// code.
//
//go:linkname trackPointer runtime.trackPointer
func trackPointer(ptr unsafe.Pointer)
