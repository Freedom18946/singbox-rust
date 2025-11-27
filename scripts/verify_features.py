#!/usr/bin/env python3
"""
Feature Verification Script for singbox-rust

This script systematically verifies all completed features across 3 layers:
1. Source Implementation - Code exists and implements the feature
2. Test Coverage - Tests exist and pass
3. Runtime Validation - Configuration works (manual step, documented)

Usage:
    python3 scripts/verify_features.py [--protocol PROTOCOL] [--category CATEGORY]
    
Examples:
    # Verify all features
    python3 scripts/verify_features.py
    
    # Verify specific protocol
    python3 scripts/verify_features.py --protocol direct
    
    # Verify category
    python3 scripts/verify_features.py --category inbound
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.absolute()

# Feature definitions with file paths
INBOUND_PROTOCOLS = {
    "socks":       {"impl": "crates/sb-adapters/src/inbound/socks/", "tests": None},
    "http":        {"impl": "crates/sb-adapters/src/inbound/http.rs", "tests": None},
    "mixed":       {"impl": "crates/sb-adapters/src/inbound/mixed.rs", "tests": None},
    "direct":      {"impl": "crates/sb-adapters/src/inbound/direct.rs", "tests": "app/tests/direct_inbound_test.rs"},
    "tun":         {"impl": "crates/sb-adapters/src/inbound/tun.rs", "tests": None},
    "redirect":    {"impl": "crates/sb-adapters/src/inbound/redirect.rs", "tests": None},
    "tproxy":      {"impl": "crates/sb-adapters/src/inbound/tproxy.rs", "tests": None},
    "shadowsocks": {"impl": "crates/sb-adapters/src/inbound/shadowsocks.rs", "tests": None},
    "vmess":       {"impl": "crates/sb-adapters/src/inbound/vmess.rs", "tests": None},
    "vless":       {"impl": "crates/sb-adapters/src/inbound/vless.rs", "tests": None},
    "trojan":      {"impl": "crates/sb-adapters/src/inbound/trojan.rs", "tests": None},
    "tuic":        {"impl": "crates/sb-adapters/src/inbound/tuic.rs", "tests": "app/tests/tuic_inbound_test.rs"},
    "hysteria":    {"impl": "crates/sb-adapters/src/inbound/hysteria.rs", "tests": "app/tests/hysteria_inbound_test.rs"},
    "hysteria2":   {"impl": "crates/sb-adapters/src/inbound/hysteria2.rs", "tests": None},
    "naive":       {"impl": "crates/sb-adapters/src/inbound/naive.rs", "tests": "app/tests/naive_inbound_test.rs"},
    "shadowtls":   {"impl": "crates/sb-adapters/src/inbound/shadowtls.rs", "tests": None},
    "anytls":      {"impl": "crates/sb-adapters/src/inbound/anytls.rs", "tests": None},
}

OUTBOUND_PROTOCOLS = {
    "direct":      {"impl": "crates/sb-adapters/src/register.rs", "tests": "app/tests/direct_block_outbound_test.rs", "lines": "1198-1238"},
    "block":       {"impl": "crates/sb-adapters/src/register.rs", "tests": "app/tests/direct_block_outbound_test.rs", "lines": "1240-1289"},
    "dns":         {"impl": "crates/sb-adapters/src/outbound/", "tests": "app/tests/dns_outbound_e2e.rs"},
    "socks":       {"impl": "crates/sb-adapters/src/outbound/socks5.rs", "tests": None},
    "http":        {"impl": "crates/sb-adapters/src/outbound/http.rs", "tests": None},
    "shadowsocks": {"impl": "crates/sb-adapters/src/outbound/shadowsocks.rs", "tests": None},
    "vmess":       {"impl": "crates/sb-adapters/src/outbound/vmess.rs", "tests": None},
    "vless":       {"impl": "crates/sb-adapters/src/outbound/vless.rs", "tests": None},
    "trojan":      {"impl": "crates/sb-adapters/src/outbound/trojan.rs", "tests": None},
    "tuic":        {"impl": "crates/sb-core/src/outbound/tuic.rs", "tests": "app/tests/tuic_outbound_e2e.rs"},
    "hysteria":    {"impl": "crates/sb-core/src/outbound/hysteria/v1.rs", "tests": "app/tests/hysteria_outbound_test.rs"},
    "hysteria2":   {"impl": "crates/sb-core/src/outbound/hysteria2.rs", "tests": "app/tests/hysteria2_udp_e2e.rs"},
    "shadowtls":   {"impl": "crates/sb-adapters/src/outbound/shadowtls.rs", "tests": None},
    "ssh":         {"impl": "crates/sb-core/src/outbound/ssh_stub.rs", "tests": None},
    "tor":         {"impl": "crates/sb-adapters/src/register.rs", "tests": "app/tests/tor_outbound_test.rs", "lines": "1297-1361"},
    "anytls":      {"impl": "crates/sb-adapters/src/outbound/anytls.rs", "tests": "app/tests/anytls_outbound_test.rs"},
    "wireguard":   {"impl": "crates/sb-core/src/outbound/wireguard.rs", "tests": None},
    "selector":    {"impl": "crates/sb-adapters/src/outbound/selector.rs", "tests": None},
    "urltest":     {"impl": "crates/sb-adapters/src/outbound/urltest.rs", "tests": None},
}

class VerificationResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.timestamp = datetime.now().isoformat()
        self.layer1_pass = False
        self.layer1_details = ""
        self.layer2_pass = False
        self.layer2_details = ""
        self.layer3_pass = False
        self.layer3_details = ""
        self.issues = []
    
    def status(self) -> str:
        if all([self.layer1_pass, self.layer2_pass, self.layer3_pass]):
            return "✅ VERIFIED"
        elif any([self.layer1_pass, self.layer2_pass]):
            return "⚠️ PARTIAL"
        else:
            return "❌ FAILED"

def run_command(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    try:
        process = subprocess.run(
            cmd,
            cwd=cwd or PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120
        )
        return process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def verify_layer1_source(protocol: str, info: Dict, category: str) -> Tuple[bool, str]:
    """Layer 1: Verify source implementation exists"""
    impl_path = PROJECT_ROOT / info["impl"]
    
    if not impl_path.exists():
        return False, f"Implementation file not found: {info['impl']}"
    
    if impl_path.is_dir():
        # Check if directory contains implementation files
        rs_files = list(impl_path.glob("*.rs"))
        if not rs_files:
            return False, f"No Rust files found in {info['impl']}"
        return True, f"Implementation directory with {len(rs_files)} files"
    else:
        # Single file implementation
        size = impl_path.stat().st_size
        with open(impl_path, 'r') as f:
            lines = len(f.readlines())
        return True, f"Implementation file: {lines} lines, {size} bytes"

def verify_layer2_tests(protocol: str, info: Dict, category: str) -> Tuple[bool, str]:
    """Layer 2: Verify tests exist and pass"""
    if "tests" not in info or info["tests"] is None:
        # Check if tests exist in adapter_instantiation_e2e or similar
        returncode, stdout, stderr = run_command([
            "cargo", "test", "-p", "app", "--lib", "--quiet",
            "--", protocol, "--nocapture"
        ])
        
        if "test result: ok" in stdout or "test result: ok" in stderr:
            return True, f"Tests pass (found in integration tests)"
        else:
            return False, f"No dedicated test file found, integration tests inconclusive"
    
    test_path = PROJECT_ROOT / info["tests"]
    if not test_path.exists():
        return False, f"Test file not found: {info['tests']}"
    
    # Run the specific test
    test_name = test_path.stem  # e.g., "direct_inbound_test"
    returncode, stdout, stderr = run_command([
        "cargo", "test", "-p", "app", "--test", test_name, "--quiet"
    ])
    
    if returncode == 0:
        # Count passed tests
        test_count = stdout.count(" ok") + stderr.count(" ok")
        return True, f"Test file exists, {test_count} tests pass"
    else:
        return False, f"Tests exist but failed: {stderr[:200]}"

def verify_layer3_runtime(protocol: str, info: Dict, category: str) -> Tuple[bool, str]:
    """Layer 3: Runtime validation (manual - just document requirements)"""
    # This layer requires manual testing with actual configurations
    # For now, we just document what needs to be tested
    requirements = []
    
    if category == "inbound":
        requirements.append("TCP connection acceptance")
        if protocol in ["socks", "shadowsocks", "hysteria", "hysteria2", "tuic"]:
            requirements.append("UDP relay")
        if protocol in ["shadowsocks", "vmess", "vless", "trojan"]:
            requirements.append("Authentication")
    elif category == "outbound":
        requirements.append("TCP connection establishment")
        if protocol in ["socks", "shadowsocks", "hysteria", "hysteria2", "tuic"]:
            requirements.append("UDP support")
    
    return False, f"MANUAL TEST REQUIRED: {', '.join(requirements)}"

def verify_protocol(protocol: str, info: Dict, category: str) -> VerificationResult:
    """Verify a single protocol across all 3 layers"""
    result = VerificationResult(protocol, category)
    
    print(f"\n{'='*60}")
    print(f"Verifying {category.upper()} protocol: {protocol}")
    print(f"{'='*60}")
    
    # Layer 1: Source Implementation
    print(f"\n[Layer 1] Checking source implementation...")
    result.layer1_pass, result.layer1_details = verify_layer1_source(protocol, info, category)
    print(f"  {'✓' if result.layer1_pass else '✗'} {result.layer1_details}")
    
    # Layer 2: Test Coverage
    print(f"\n[Layer 2] Checking test coverage...")
    result.layer2_pass, result.layer2_details = verify_layer2_tests(protocol, info, category)
    print(f"  {'✓' if result.layer2_pass else '✗'} {result.layer2_details}")
    
    # Layer 3: Runtime Validation
    print(f"\n[Layer 3] Runtime validation requirements...")
    result.layer3_pass, result.layer3_details = verify_layer3_runtime(protocol, info, category)
    print(f"  {result.layer3_details}")
    
    print(f"\n{'─'*60}")
    print(f"Status: {result.status()}")
    print(f"{'─'*60}")
    
    return result

def main(args):
    """Main verification process"""
    results = []
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║   singbox-rust Feature Verification System                  ║
║   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                         ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Determine what to verify
    categories = {
        "inbound": INBOUND_PROTOCOLS,
        "outbound": OUTBOUND_PROTOCOLS,
    }
    
    if hasattr(args, 'category') and args.category:
        categories = {args.category: categories[args.category]}
    
    for category, protocols in categories.items():
        if hasattr(args, 'protocol') and args.protocol:
            if args.protocol not in protocols:
                print(f"Protocol '{args.protocol}' not found in {category}")
                continue
            protocols = {args.protocol: protocols[args.protocol]}
        
        for protocol, info in protocols.items():
            result = verify_protocol(protocol, info, category)
            results.append(result)
    
    # Summary
    print(f"\n\n{'='*60}")
    print(f"VERIFICATION SUMMARY")
    print(f"{'='*60}\n")
    
    verified = sum(1 for r in results if r.status() == "✅ VERIFIED")
    partial = sum(1 for r in results if r.status() == "⚠️ PARTIAL")
    failed = sum(1 for r in results if r.status() == "❌ FAILED")
    
    print(f"Total Features: {len(results)}")
    print(f"  ✅ Verified: {verified}")
    print(f"  ⚠️ Partial: {partial}")
    print(f"  ❌ Failed: {failed}")
    
    print(f"\n{'─'*60}")
    for result in results:
        print(f"{result.status():<15} {result.category:>10}/{result.name}")
    
    # Export results to JSON
    output_file = PROJECT_ROOT / "verification_results.json"
    with open(output_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "results": [
                {
                    "name": r.name,
                    "category": r.category,
                    "status": r.status(),
                    "layer1": r.layer1_pass,
                    "layer2": r.layer2_pass,
                    "layer3": r.layer3_pass,
                    "details": {
                        "layer1": r.layer1_details,
                        "layer2": r.layer2_details,
                        "layer3": r.layer3_details,
                    }
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "verified": verified,
                "partial": partial,
                "failed": failed
            }
        }, f, indent=2)
    
    print(f"\nResults exported to: {output_file}")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verify singbox-rust features")
    parser.add_argument("--protocol", help="Verify specific protocol")
    parser.add_argument("--category", choices=["inbound", "outbound"], help="Verify specific category")
    args = parser.parse_args()
    
    sys.exit(main(args))
