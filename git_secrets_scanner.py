import os
import git
import tempfile
import re
import json
import time
import argparse

SECRET_PATTERNS = {
    # AWS Access Key ID - matches AKIA... format
    'AWS_ACCESS_KEY_ID': re.compile(r'(?i)^\s*[+-]?\s*(?:aws[_-]?access[_-]?key[_-]?id?|[AKIA|ASIA|ABIA])[A-Z0-9]{16}', re.MULTILINE),
    
    # AWS Secret Access Key - matches the base64-like string
    'AWS_SECRET_ACCESS_KEY': re.compile(r'(?i)^\s*[+-]?\s*(?:aws[_-]?secret[_-]?access[_-]?key|[A-Za-z0-9+/]{40,}=?$)', re.MULTILINE),
    
    # API/Stripe/OpenAI keys starting with sk_
    'API_KEY': re.compile(r'(?i)^\s*[+-]?\s*(?:api[_-]?key|secret|token|key)\s*[=:]\s*["\']?(sk[_-]?[a-z0-9_-]{20,})["\']?', re.MULTILINE),
    
    # Generic secret assignment pattern
    'GENERIC_SECRET': re.compile(r'(?i)^\s*[+-]?\s*(password|pwd|secret|token|key)\s*[=:]\s*["\']?[A-Za-z0-9_+/=-]{20,}["\']?', re.MULTILINE),
    
    # Direct AWS key patterns (standalone)
    'STANDALONE_AWS_ACCESS': re.compile(r'(?i)[AKIA|ASIA|ABIA][A-Z0-9]{16}', re.MULTILINE),
    'STANDALONE_AWS_SECRET': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}', re.MULTILINE),
    
    # Stripe/OpenAI key pattern
    'STRIPE_API_KEY': re.compile(r'(?i)sk[_-]?test[_-]?[a-z0-9]{20,}', re.MULTILINE),
}

# clean unified diff format to extract actual content
def clean_diff_for_scanning(diff_text):
    if not diff_text:
        return ""
    
    lines = diff_text.splitlines()
    cleaned_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # skip diff headers
        if line.startswith('@@'):
            i += 1
            continue
            
        # handle content lines
        if line.startswith((' ', '+', '-')):
            # remove prefix and normalize whitespace
            content = re.sub(r'^[ +-]-?\s*', '', line)
            if content.strip():
                cleaned_lines.append(content)
        
        i += 1
    
    return '\n'.join(cleaned_lines)

# scan with better matching and full snippet capture
def scan_with_heuristics(text, source="unknown", debug=False):
    if not text or len(text.strip()) < 10:
        return []
    
    if debug:
        print(f"DEBUG: Scanning {source}")
        print(f"DEBUG: Content preview:")
        for line in text.splitlines()[:5]:
            print(f"  {repr(line)}")
    
    findings = []
    lines = text.splitlines()
    
    for line_num, line in enumerate(lines, start=1):
        line_original = line
        line_clean = line.strip()
        
        if len(line_clean) < 10:
            continue
        
        # try multiple patterns, capture full context
        for type_, pattern in SECRET_PATTERNS.items():
            matches = pattern.finditer(line_original)
            for match in matches:
                matched_text = match.group(0).strip()
                
                # check if this looks like a real secret
                if len(matched_text) < 15:
                    continue
                
                # skip obvious false positives
                lower_match = matched_text.lower()
                if any(fp in lower_match for fp in ['example', 'test', 'sample', 'dummy', 'fake']):
                    continue
                
                # for AWS secret keys, capture the full line if it's an assignment
                full_snippet = matched_text
                if 'AWS_SECRET' in type_ and '=' in line_original:
                    full_snippet = line_original.strip()
                
                if debug:
                    print(f"DEBUG: MATCH in {source}: {full_snippet[:60]}... (type: {type_})")
                
                findings.append({
                    'line': line_num,
                    'snippet': full_snippet[:200],  # Capture more context
                    'type': type_,
                    'rationale': f'Matched {type_} pattern',
                    'confidence': 'high',
                    'full_line': line_original.strip()
                })
                break  # one match per line to avoid duplicates
    
    if debug:
        print(f"Heuristic scan {source}: {len(findings)} findings")
    return findings

# fallback: get the actual file content from the commit tree
def get_actual_file_content(repo, commit, file_path):
    try:
        tree = commit.tree
        if file_path in tree:
            blob = tree[file_path]
            return blob.data_stream.read().decode('utf-8', errors='ignore')
    except:
        pass
    return None

# updated to use the new patterns
def analyze_commit(commit_data, debug=False):
    findings = []
    commit_hash = commit_data['hash']
    
    # scan commit message
    msg_findings = scan_with_heuristics(commit_data['message'], f"commit message {commit_hash}", debug)
    for f in msg_findings:
        f['file'] = 'COMMIT_MESSAGE'
        findings.append({'commit_hash': commit_hash, **f})
    
    # scan diffs
    for i, diff in enumerate(commit_data['diff']):
        try:
            file_path = diff.a_path or diff.b_path or f"unknown_file_{i}"
            
            diff_text = ""
            if hasattr(diff, 'diff') and diff.diff:
                diff_text = diff.diff.decode('utf-8', errors='ignore')
                cleaned_diff = clean_diff_for_scanning(diff_text)
            else:
                cleaned_diff = ""
            
            if cleaned_diff.strip():
                print(f"Scanning file: {file_path}")
                file_findings = scan_with_heuristics(cleaned_diff, f"file {file_path}", debug)
                
                for f in file_findings:
                    f['file'] = file_path
                    findings.append({'commit_hash': commit_hash, **f})
                
                if file_findings:
                    print(f"  Found {len(file_findings)} potential secrets")
                    for f in file_findings:
                        print(f"    - {f['type']}: {f['snippet'][:80]}")
            else:
                print(f"  No content found for {file_path}")
                
        except Exception as e:
            print(f"Error processing diff {i}: {e}")
            continue
    
    print(f"Total findings for {commit_hash}: {len(findings)}")
    return findings

# get commits and keep full commit objects for fallback
def get_last_n_commits(repo, n):
    try:
        branch = 'main'
        commits = list(repo.iter_commits(branch, max_count=n))
        if not commits:
            branch = 'master'
            commits = list(repo.iter_commits(branch, max_count=n))
        
        if not commits:
            print("No commits found")
            return []
            
        print(f"Found {len(commits)} commits on {branch}")
        processed_commits = []
        
        for i, commit in enumerate(commits):
            parent = commit.parents[0] if commit.parents else None
            diff = commit.diff(parent, create_patch=True) if parent else []
            
            commit_data = {
                'hash': commit.hexsha[:8],
                'message': commit.message.strip(),
                'diff': diff,
                'full_commit': commit  # Keep full object for fallback
            }
            processed_commits.append(commit_data)
            print(f"Processing commit {i+1}/{len(commits)}: {commit_data['hash']} - {commit.message.splitlines()[0][:50]}")
        
        return processed_commits
    except Exception as e:
        print(f"Error getting commits: {e}")
        return []

# handle local vs remote repo
def get_repo(repo_path_or_url):
    try:
        if repo_path_or_url.startswith(('http', 'https', 'git')):
            import tempfile
            temp_dir = tempfile.mkdtemp()
            print(f"Cloning repo to {temp_dir}")
            repo = git.Repo.clone_from(repo_path_or_url, temp_dir)
        else:
            repo = git.Repo(repo_path_or_url)
        print(f"Working on branch: {repo.active_branch}")
        return repo
    except Exception as e:
        print(f"Error getting repo: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description='Scan Git repo for secrets.')
    parser.add_argument('--repo', required=True, help='Repo path or URL')
    parser.add_argument('--n', type=int, default=5, help='Number of commits')
    parser.add_argument('--out', default='report.json', help='Output JSON file')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    
    start_time = time.time()
    
    try:
        repo = get_repo(args.repo)
        commits = get_last_n_commits(repo, args.n)
        
        if not commits:
            print("No commits to analyze!")
            return
        
        all_findings = []
        
        for i, commit in enumerate(commits, 1):
            print(f"\n--- Analyzing commit {i}/{len(commits)} ---")
            commit_findings = analyze_commit(commit, debug=args.debug)
            all_findings.extend(commit_findings)
        
        output = {
            'summary': {
                'total_commits_scanned': len(commits),
                'total_findings': len(all_findings),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'findings': all_findings
        }
        
        with open(args.out, 'w') as f:
            json.dump(output, f, indent=2)
        
        elapsed = time.time() - start_time
        print(f"\nReport saved to {args.out}")
        print(f"Total time: {elapsed:.1f}s")
        print(f"Found {len(all_findings)} potential secrets")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
