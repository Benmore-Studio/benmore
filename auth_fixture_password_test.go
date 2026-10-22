//go:build !cli

package main

// fixturePassword is the password the auth tests give their accounts. It is
// generated per run, so the sources hold no credential-shaped literal.
var fixturePassword = "Fx!" + generateToken(12)
