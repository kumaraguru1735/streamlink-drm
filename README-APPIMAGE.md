# Streamlink AppImage Build System

This directory contains the build system for creating AppImage binaries of Streamlink.

## Files

- `config.yml` - Build configuration including dependencies and bundle settings
- `build.sh` - Main build script
- `build-docker.sh` - Docker container build script
- `get-dependencies.sh` - Dependency resolution script
- `deploy.sh` - GitHub release deployment script
- `requirements.txt` - Build dependencies
- `.github/workflows/appimage.yml` - Main CI/CD workflow
- `.github/workflows/preview-appimage.yml` - Preview build workflow

## Usage

### Local Build

1. Install dependencies:
   ```bash
   # On Ubuntu/Debian
   sudo apt install git jq docker.io
   pip install yq
   ```

2. Build AppImage:
   ```bash
   # Build for current architecture without bundles
   ./build.sh
   
   # Build for specific architecture with FFmpeg bundle
   ./build.sh --arch x86_64 --bundle ffmpeg
   
   # Build from specific git ref
   ./build.sh --gitref v5.0.0 --bundle ffmpeg
   ```

3. Find the built AppImage in the `dist/` directory.

### GitHub Actions

The build system includes two workflows:

1. **appimage.yml** - Builds AppImages on push/PR and deploys on tags
2. **preview-appimage.yml** - Manual workflow for testing specific git refs

### Configuration

The `config.yml` file contains:

- Application metadata (name, entry point)
- Git repository information
- Build environments for each architecture
- Dependency lists with hashes
- Bundle configurations (like FFmpeg)

### Dependencies

Dependencies are managed with cryptographic hashes for security. To update dependencies:

```bash
./get-dependencies.sh --arch x86_64 > new-deps.yml
```

### Bundles

Bundles are additional software packaged with the AppImage:

- **ffmpeg** - Includes FFmpeg binary for stream processing

## Architecture Support

- **x86_64** - Standard 64-bit Intel/AMD processors
- **aarch64** - 64-bit ARM processors (Apple Silicon, Raspberry Pi, etc.)

## Requirements

- Docker
- Git
- jq
- yq (Python package)
- curl (for bundle downloads)

## Troubleshooting

### Build Fails

1. Check Docker is running and accessible
2. Verify all dependencies are installed
3. Check network connectivity for bundle downloads
4. Ensure sufficient disk space

### Bundle Issues

1. Verify bundle URLs are accessible
2. Check SHA256 hashes match
3. Update bundle configuration if needed

### Dependency Issues

1. Run `get-dependencies.sh` to refresh dependency hashes
2. Check Docker image compatibility
3. Verify Python version compatibility

## Contributing

1. Test builds locally before submitting PRs
2. Update dependency hashes when adding new dependencies
3. Test both architectures if possible
4. Update this README for any new features
