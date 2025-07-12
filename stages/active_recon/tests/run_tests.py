#!/usr/bin/env python3
"""
Test runner for Active Recon stage tests
"""

import unittest
import sys
import os
import time
import json
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))


# Global test modules configuration
TEST_MODULES = [
    'test_nmap_runner',
    'test_naabu_runner',
    'test_katana_runner',
    'test_feroxbuster_runner',
    'test_getjs_runner',
    'test_linkfinder_runner',
    'test_arjun_runner',
    'test_webanalyze_runner',
    'test_eyewitness_runner',
    'test_eyeballer_runner',
    'test_active_recon_workflow',
    'test_integration',
    'test_runner_utils'
]

def run_all_tests():
    """Run all tests for the active_recon stage"""
    print("=" * 80)
    print("ACTIVE RECON STAGE - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Test results storage
    test_results = {
        'start_time': datetime.now().isoformat(),
        'test_suites': [],
        'summary': {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'errors': 0,
            'skipped': 0
        }
    }

    # Use global test modules
    test_modules = TEST_MODULES.copy()

    # Test categories
    test_categories = {
        'unit_tests': [
            'test_nmap_runner',
            'test_naabu_runner',
            'test_katana_runner',
            'test_feroxbuster_runner',
            'test_getjs_runner',
            'test_linkfinder_runner',
            'test_arjun_runner',
            'test_webanalyze_runner',
            'test_eyewitness_runner',
            'test_eyeballer_runner',
            'test_runner_utils'
        ],
        'integration_tests': ['test_integration'],
        'workflow_tests': ['test_active_recon_workflow']
    }

    total_start_time = time.time()

    # Run tests by category
    for category, modules in test_categories.items():
        print(f"\n{'='*20} {category.upper()} {'='*20}")
        
        for module_name in modules:
            if module_name in test_modules:
                print(f"\nRunning {module_name}...")
                
                try:
                    # Import and run the test module
                    module = __import__(module_name)
                    
                    # Create test suite
                    loader = unittest.TestLoader()
                    suite = loader.loadTestsFromModule(module)
                    
                    # Run tests
                    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
                    result = runner.run(suite)
                    
                    # Store results
                    suite_result = {
                        'module': module_name,
                        'category': category,
                        'tests_run': result.testsRun,
                        'failures': len(result.failures),
                        'errors': len(result.errors),
                        'skipped': len(result.skipped) if hasattr(result, 'skipped') else 0,
                        'success': result.wasSuccessful(),
                        'failures_details': result.failures,
                        'errors_details': result.errors
                    }
                    
                    test_results['test_suites'].append(suite_result)
                    
                    # Update summary
                    test_results['summary']['total_tests'] += result.testsRun
                    test_results['summary']['failed'] += len(result.failures)
                    test_results['summary']['errors'] += len(result.errors)
                    test_results['summary']['skipped'] += suite_result['skipped']
                    test_results['summary']['passed'] += (result.testsRun - len(result.failures) - len(result.errors) - suite_result['skipped'])
                    
                    # Print module summary
                    if result.wasSuccessful():
                        print(f"✅ {module_name}: {result.testsRun} tests passed")
                    else:
                        print(f"❌ {module_name}: {len(result.failures)} failures, {len(result.errors)} errors")
                        
                except ImportError as e:
                    print(f"⚠️  Could not import {module_name}: {e}")
                    test_results['test_suites'].append({
                        'module': module_name,
                        'category': category,
                        'error': f'Import error: {e}',
                        'success': False
                    })
                except Exception as e:
                    print(f"❌ Error running {module_name}: {e}")
                    test_results['test_suites'].append({
                        'module': module_name,
                        'category': category,
                        'error': f'Runtime error: {e}',
                        'success': False
                    })

    total_end_time = time.time()
    test_results['end_time'] = datetime.now().isoformat()
    test_results['total_duration'] = total_end_time - total_start_time

    # Print final summary
    print("\n" + "=" * 80)
    print("TEST EXECUTION SUMMARY")
    print("=" * 80)
    
    summary = test_results['summary']
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Errors: {summary['errors']}")
    print(f"Skipped: {summary['skipped']}")
    print(f"Success Rate: {(summary['passed'] / summary['total_tests'] * 100):.1f}%" if summary['total_tests'] > 0 else "Success Rate: N/A")
    print(f"Total Duration: {test_results['total_duration']:.2f} seconds")
    
    # Print detailed results
    print("\n" + "=" * 80)
    print("DETAILED RESULTS")
    print("=" * 80)
    
    for suite in test_results['test_suites']:
        if suite.get('success', False):
            print(f"✅ {suite['module']} ({suite['category']}): {suite['tests_run']} tests passed")
        else:
            if 'error' in suite:
                print(f"❌ {suite['module']} ({suite['category']}): {suite['error']}")
            else:
                print(f"❌ {suite['module']} ({suite['category']}): {suite['failures']} failures, {suite['errors']} errors")
                
                # Print failure details
                if suite.get('failures'):
                    print("  Failures:")
                    for test, traceback in suite['failures']:
                        print(f"    - {test}: {traceback.split('AssertionError:')[-1].strip()}")
                
                # Print error details
                if suite.get('errors'):
                    print("  Errors:")
                    for test, traceback in suite['errors']:
                        print(f"    - {test}: {traceback.split('Exception:')[-1].strip()}")

    # Save test results to file
    results_file = os.path.join(os.path.dirname(__file__), 'test_results.json')
    with open(results_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    
    print(f"\nTest results saved to: {results_file}")
    
    # Return overall success
    overall_success = all(suite.get('success', False) for suite in test_results['test_suites'])
    
    if overall_success:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("\n💥 SOME TESTS FAILED!")
        return 1


def run_specific_test_category(category):
    """Run tests for a specific category"""
    global TEST_MODULES
    
    categories = {
        'unit': [
            'test_nmap_runner',
            'test_naabu_runner',
            'test_katana_runner',
            'test_feroxbuster_runner',
            'test_getjs_runner',
            'test_linkfinder_runner',
            'test_arjun_runner',
            'test_webanalyze_runner',
            'test_eyewitness_runner',
            'test_eyeballer_runner',
            'test_runner_utils'
        ],
        'integration': ['test_integration'],
        'workflow': ['test_active_recon_workflow'],
        'all': [
            'test_nmap_runner',
            'test_naabu_runner',
            'test_katana_runner',
            'test_feroxbuster_runner',
            'test_getjs_runner',
            'test_linkfinder_runner',
            'test_arjun_runner',
            'test_webanalyze_runner',
            'test_eyewitness_runner',
            'test_eyeballer_runner',
            'test_runner_utils',
            'test_integration',
            'test_active_recon_workflow'
        ]
    }
    
    if category not in categories:
        print(f"Unknown category: {category}")
        print(f"Available categories: {', '.join(categories.keys())}")
        return 1
    
    print(f"Running {category} tests...")
    
    # Temporarily modify test modules to only include the specified category
    original_modules = TEST_MODULES.copy()
    TEST_MODULES = categories[category]
    
    try:
        return run_all_tests()
    finally:
        TEST_MODULES = original_modules


def run_specific_test_module(module_name):
    """Run tests for a specific module"""
    print(f"Running {module_name}...")
    
    try:
        module = __import__(module_name)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    except ImportError as e:
        print(f"Could not import {module_name}: {e}")
        return 1
    except Exception as e:
        print(f"Error running {module_name}: {e}")
        return 1


def main():
    """Main function to handle command line arguments"""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'category' and len(sys.argv) > 2:
            return run_specific_test_category(sys.argv[2])
        elif command == 'module' and len(sys.argv) > 2:
            return run_specific_test_module(sys.argv[2])
        elif command == 'help':
            print("Active Recon Test Runner")
            print("Usage:")
            print("  python run_tests.py                    # Run all tests")
            print("  python run_tests.py category <cat>     # Run specific category (unit, integration, workflow, all)")
            print("  python run_tests.py module <module>    # Run specific module")
            print("  python run_tests.py help               # Show this help")
            return 0
        else:
            print(f"Unknown command: {command}")
            print("Use 'python run_tests.py help' for usage information")
            return 1
    else:
        return run_all_tests()


if __name__ == '__main__':
    sys.exit(main()) 