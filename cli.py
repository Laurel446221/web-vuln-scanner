import argparse
import sys
from scanner import WebVulnerabilityScanner
from active_scanner import ActiveVulnerabilityScanner

def main():
    banner = """
╔════════════════════════════════════════════════════════════════╗
║                    WEB VULNERABILITY SCANNER                  ║
║                   Developed by Laurel Megida                  ║
╚════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    
    subparsers = parser.add_subparsers(dest='command', help='Scanning modes')
    
    # Basic scan
    basic_parser = subparsers.add_parser('basic', help='Basic vulnerability assessment')
    basic_parser.add_argument('-t', '--target', required=True, help='Target domain or IP')
    basic_parser.add_argument('-p', '--ports', nargs='+', default=[80, 443, 8080, 21, 22], 
                            help='Ports to scan')
    
    # Active scan  
    active_parser = subparsers.add_parser('active', help='Active vulnerability testing')
    active_parser.add_argument('-t', '--target', required=True, help='Target URL')
    active_parser.add_argument('-d', '--delay', type=float, default=0.5, 
                             help='Delay between requests')
    
    # Full scan
    full_parser = subparsers.add_parser('full', help='Comprehensive security assessment')
    full_parser.add_argument('-t', '--target', required=True, help='Target to scan')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'basic':
            scanner = WebVulnerabilityScanner(args.target, ports=args.ports)
            scanner.run_comprehensive_scan()
            
        elif args.command == 'active':
            scanner = ActiveVulnerabilityScanner(args.target, delay=args.delay)
            scanner.run_scan()
            
        elif args.command == 'full':
            # Run both basic and active scans
            print("[*] Starting comprehensive security assessment...")
            basic_scanner = WebVulnerabilityScanner(args.target)
            basic_scanner.run_comprehensive_scan()
            
            print("\n[*] Starting active vulnerability testing...")
            active_scanner = ActiveVulnerabilityScanner(args.target)
            active_scanner.run_scan()
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()