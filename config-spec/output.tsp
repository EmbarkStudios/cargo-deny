model Output {
  /**
   * The maximum depth that features will be displayed when inclusion graphs are shown in
   * diagnostics, unless specified via `--feature-depth` on the command line. Only applies to
   * diagnostics that actually print features.
   */
  `feature-depth`?: uint32 = 1;
}
