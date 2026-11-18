// Package rotate builds the rotation manifest `keys rotate` signs: it carries
// the previous manifest forward, guards the epoch, and refuses a manifest an
// updater would refuse. The rules are sigillum spec 0008's.
package rotate
