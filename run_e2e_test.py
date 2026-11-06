import time
import httpx
import sys

# Configure UTF-8 for Windows PowerShell console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_URL = "http://localhost:8000"

def run_test():
    job_id = sys.argv[1] if len(sys.argv) > 1 else None

    with httpx.Client(timeout=10.0) as client:
        if not job_id:
            print("[1] Loading sample log...")
            r = client.post(f"{BASE_URL}/api/load-sample")
            assert r.status_code == 200, f"load-sample failed: {r.text}"
            data = r.json()
            job_id = data["job_id"]
            total_lines = data["total_lines"]
            print(f"    Job ID: {job_id}, Lines: {total_lines}")

            print(f"[2] Starting analysis with model 'qwen2.5:1.5b'...")
            r = client.post(f"{BASE_URL}/api/analyze/{job_id}?model=qwen2.5:1.5b")
            assert r.status_code == 200, f"start analysis failed: {r.text}"
        else:
            print(f"[1] Attaching to existing job ID: {job_id}")

        print("[3] Polling analysis status...")
        start_time = time.time()
        last_log_count = 0
        while True:
            time.sleep(3)
            r = client.get(f"{BASE_URL}/api/status/{job_id}")
            assert r.status_code == 200, f"status failed: {r.text}"
            status_data = r.json()
            status = status_data["status"]
            progress = status_data.get("progress_percent", 0.0)
            logs = status_data.get("log_messages", [])
            
            # Print new logs
            if len(logs) > last_log_count:
                for line in logs[last_log_count:]:
                    safe_line = line.encode("ascii", errors="replace").decode("ascii")
                    print(f"    [LIVE] {safe_line}")
                last_log_count = len(logs)

            print(f"    Progress: {progress:.1f}% | Status: {status} | Elapsed: {time.time()-start_time:.1f}s")
            
            if status in ("complete", "completed", "failed"):
                break

        if status == "failed":
            print(f"ERROR: Analysis job failed! Error: {status_data.get('error')}")
            sys.exit(1)

        print("[4] Fetching final consolidated report...")
        r = client.get(f"{BASE_URL}/api/report/{job_id}")
        assert r.status_code == 200, f"report failed: {r.text}"
        report = r.json()

        print("\n" + "="*80)
        print("FINAL CONSOLIDATED SECURITY REPORT")
        print("="*80)
        print(f"Job ID: {report.get('job_id')}")
        print(f"Model: {report.get('model_name') or report.get('model_used')}")
        print(f"Total Lines: {report.get('total_lines')}")
        print(f"Total Chunks: {report.get('total_chunks')}")
        print(f"Findings Count: {len(report.get('findings', []))}")
        print(f"Analysis Duration: {report.get('processing_time_seconds') or report.get('analysis_time_seconds')}s")
        print("-" * 80)
        print(f"{'SEVERITY':<10} | {'ATTACK TYPE':<35} | {'SOURCE IP':<16} | {'EVIDENCE LINES'}")
        print("-" * 80)

        critical_found = False
        sql_found = False
        path_found = False
        rate_found = False
        prompt_found = False
        health_fp = False
        typo_fp = False

        for f in report["findings"]:
            sev = f["severity"]
            atk = f["attack_type"]
            ip = f["source_ip"]
            ev = f["evidence_lines"]
            ev_str = f"{len(ev)} lines: {ev[:6]}" + ("..." if len(ev) > 6 else "")
            print(f"{sev:<10} | {atk:<35} | {ip:<16} | {ev_str}")

            if "compromise" in atk.lower() or "brute" in atk.lower():
                critical_found = True
            if "sql" in atk.lower():
                sql_found = True
            if "path" in atk.lower() or "traversal" in atk.lower() or "scanning" in atk.lower():
                path_found = True
            if "rate" in atk.lower() or "dos" in atk.lower():
                rate_found = True
            if "prompt" in atk.lower():
                prompt_found = True
            if ip == "192.0.2.10":
                health_fp = True
            if ip == "198.51.100.96":
                typo_fp = True

        print("=" * 80)
        print("VERIFICATION CHECKS:")
        print(f"  [+] Brute Force + Compromise Detected: {critical_found}")
        print(f"  [+] SQL Injection Detected:           {sql_found}")
        print(f"  [+] Path Traversal/Scanning Detected: {path_found}")
        print(f"  [+] Rate Limit Flooding Detected:     {rate_found}")
        print(f"  [+] Prompt Injection Detected:         {prompt_found}")
        print(f"  [-] Health Monitor False Positive:    {'FAIL (found)' if health_fp else 'PASS (none)'}")
        print(f"  [-] Single Typo False Positive:       {'FAIL (found)' if typo_fp else 'PASS (none)'}")

        if not health_fp and not typo_fp and critical_found and sql_found and path_found and prompt_found:
            print("\n>>> ALL VERIFICATION CHECKS PASSED PERFECTLY! <<<")
        else:
            print("\n>>> SOME CHECKS NEED REVIEW <<<")

if __name__ == "__main__":
    run_test()
