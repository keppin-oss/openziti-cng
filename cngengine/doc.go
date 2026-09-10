// Package cngengine registers a Windows CNG/KSP identity engine with OpenZiti's
// identity package.
//
// OpenZiti's identity module resolves a key reference by treating the URL scheme
// as an engine identifier. This package registers a "cng" engine that maps an
// OpenZiti key reference to an existing machine-scoped, non-exportable
// Microsoft Software Key Storage Provider key owned by Keppin-OSS CNG.
//
// The engine never owns CNG/KSP mechanics. It delegates all key custody and
// signing to github.com/keppin-oss/cng/windowscng and only supplies
// the minimal OpenZiti Engine adapter plus the stable key-reference syntax.
package cngengine




