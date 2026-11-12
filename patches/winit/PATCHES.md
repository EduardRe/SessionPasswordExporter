# Local patch

This directory contains the `winit` 0.30.13 source with one local Windows fix.

The Windows event loop handles `WM_INPUTLANGCHANGE` by refreshing the keyboard-layout cache before forwarding the message to `DefWindowProcW`. This backports the fix from upstream [PR #4582](https://github.com/rust-windowing/winit/pull/4582), which addresses event-loop freezes with Punto Switcher and similar layout-switching tools.

Remove the `[patch.crates-io]` override from the root `Cargo.toml` and this directory once a compatible `winit` 0.30 release includes the fix.
