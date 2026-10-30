{ pkgs }:
let
  inherit (pkgs) lib;
  src = lib.cleanSourceWith {
    src = ../..;
    filter = path: type:
      !(builtins.elem (baseNameOf path) [ "target" ".git" ".aide" ".agents" ".codex" "node_modules" "docs" ])
      && lib.cleanSourceFilter path type;
  };
  version = (builtins.fromTOML (builtins.readFile ../../Cargo.toml)).workspace.package.version;
  names = [ "bitwarden-pm" "bitwarden-sm" "gnome-keyring" "keepassxc-file" "protonpass" ];
  guests = map (name:
    let
      crate = "rosec-${name}";
      wasm = "${builtins.replaceStrings [ "-" ] [ "_" ] crate}.wasm";
    in pkgs.pkgsCross.wasi32.rustPlatform.buildRustPackage {
      pname = crate;
      inherit version src;
      sourceRoot = "source/${crate}";
      cargoLock.lockFile = ../../. + "/${crate}/Cargo.lock";
      nativeBuildInputs = [ pkgs.lld ];
      env.RUSTFLAGS = "-C linker=wasm-ld";
      # WASI guests cannot run native cargo tests. Host loading is tested below.
      doCheck = false;
      postInstall = ''
        mkdir -p $out/lib/rosec/providers
        mv $out/bin/${wasm} $out/lib/rosec/providers/
        cp ${wasm}.policy.toml $out/lib/rosec/providers/
      '';
    }) names;
  providers = pkgs.symlinkJoin { name = "rosec-providers-${version}"; paths = guests; };
  trust = pkgs.runCommand "rosec-packaged-providers.json" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    bundles=()
    for wasm in ${providers}/lib/rosec/providers/*.wasm; do
      bundles+=(--bundle "$wasm" "$wasm.policy.toml" "$wasm")
    done
    python ${../packaged-providers.py} "''${bundles[@]}" > $out
  '';
  rosec = pkgs.rustPlatform.buildRustPackage {
    pname = "rosec";
    inherit version src;
    cargoLock = {
      lockFile = ../../Cargo.lock;
      # Every git dependency has a full revision in Cargo.lock.
      allowBuiltinFetchGit = true;
    };
    nativeBuildInputs = [ pkgs.pkg-config pkgs.dbus pkgs.autoPatchelfHook ];
    buildInputs = [ pkgs.pam pkgs.stdenv.cc.cc.lib ];
    runtimeDependencies = [ pkgs.wayland pkgs.libxkbcommon ];
    env.ROSEC_PACKAGED_PROVIDERS = trust;
    preCheck = ''
      export HOME=$TMPDIR/home XDG_DATA_HOME=$TMPDIR/xdg-data
      mkdir -p "$HOME" "$XDG_DATA_HOME"
      export $(dbus-launch --config-file=${pkgs.dbus}/share/dbus-1/session.conf)
      mkdir -p rosec-keepassxc-file/target/wasm32-wasip1/release
      ln -s ${providers}/lib/rosec/providers/rosec_keepassxc_file.wasm \
        rosec-keepassxc-file/target/wasm32-wasip1/release/rosec_keepassxc_file.wasm
    '';
    postCheck = ''
      cargo test --release --locked --offline --target ${pkgs.stdenv.hostPlatform.rust.rustcTarget} \
        -p rosec-wasm keepassxc_totp -- --ignored
    '';
    postBuild = ''
      make -C contrib/pam ROSEC_PAM_UNLOCK_PATH=$out/libexec/rosec/rosec-pam-unlock
    '';
    postInstall = ''
      mkdir -p $out/libexec/rosec $out/lib/security $out/lib/rosec
      mv $out/bin/rosec-pam-unlock $out/libexec/rosec/
      cp contrib/pam/pam_rosec.so $out/lib/security/
      ln -s ${providers}/lib/rosec/providers $out/lib/rosec/providers
      XDG_CONFIG_HOME=$out/lib XDG_DATA_HOME=$out/share $out/bin/rosec enable
    '';
    meta.platforms = lib.platforms.linux;
    meta.mainProgram = "rosec";
  };
  smoke = pkgs.runCommand "rosec-provider-smoke" { nativeBuildInputs = [ rosec ]; } ''
    export HOME=$TMPDIR/home XDG_CONFIG_HOME=$TMPDIR/config XDG_DATA_HOME=$TMPDIR/data
    mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME/rosec/providers"
    # This performs discovery, manifest execution and authenticity validation.
    # No config disables verification and no release/private keys are supplied.
    rosec provider validate > report
    for kind in ${lib.escapeShellArgs names}; do
      grep -F "$kind (" report
    done
    grep -F 'embedded package hashes' report
    # An identical unsigned copy at a user-controlled path must not gain trust.
    wasm=${providers}/lib/rosec/providers/rosec_gnome_keyring.wasm
    cp "$wasm" "$wasm.policy.toml" "$XDG_DATA_HOME/rosec/providers/"
    if rosec provider validate --wasm "$XDG_DATA_HOME/rosec/providers/rosec_gnome_keyring.wasm"; then
      echo 'Unsigned user copy unexpectedly accepted' >&2
      exit 1
    fi
    mkdir -p $out
    cp report $out/
  '';
in { inherit rosec providers smoke; }
