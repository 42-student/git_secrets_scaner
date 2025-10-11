import os
import git
import tempfile
import re
import ollama

# common regex patterns for secrets
SECRET_PATTERNS = {
	'API_KEY': re.compile(r'(?i)(api_key|apikey|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9+/=]{20,}["\']?'),
	'AWS_KEY': re.compile(r'(?i)AKIA[0-9A-Z]{16}'),
	# add more e.g. private keys, high-entropy checks
}

# handles local vs. remote repo
def get_repo(repo_path_or_url):
	if repo_path_or_url.startswith(('http', 'https', 'git')):
		temp_dir = tempfile.mkdtemp()
		return git.Repo.clone_from(repo_path_or_url, temp_dir)
	else:
		return git.Repo(repo_path_or_url)

# iterates recent commits, gets hash/message and diff as patch(text format)
def get_last_n_commits(repo, n):
	commits = []
	for commit in repo.iter_commits('main', max_count = n):
		commit_data = {
			'hash': commit.hexsha,
			'message': commit.message.strip(),
			'diff': commit.diff(commit.parents[0] if commit.parents else None, create_patch=True)
		}
		commits.append(commit_data)
	return commits

# TESTING git repo handling and commit extraction
#if __name__ == '__main__': repo = get_repo('https://github.com/42-student/libunit'); commits = get_last_n_commits(repo, 5); print(commits[1])

# quick regex to flag suspects
def scan_with_heuristics(text):
	findings = []
	for line_num, line in enumerate(text.splitlines(), start=1):
		for type_, pattern in SECRET_PATTERNS.items():
			if match := pattern.search(line):
				findings.append({
					'line': line_num,
					'snippet': line.strip(),
					'type': type_,
					'rationale': 'Matched regex patterns',
					'confidence': 'medium'	# LLM will refine
				})
	return findings

# contextual analysis; we truncate text to fit context window
def scan_with_llm(text):
	prompt = f"""
	Analyze this Git diff or commit message for sensitive data like API keys, passwords, private keys, or other secrets.
	Consider context: ignore sample code or non-secrets.
	Output only JSON array: [{{"file": "str", "snippet": "str", "type": "str", "rationale": "str", "confidence": "high|medium|low"}}]
	Text: {text[:2000]}
	"""
	response = ollama.generate(model='llama3', prompt=prompt)
	try:
		return eval(response['response'])
	except:
		return []

# reduces false positives by cross-checking
def analyze_commit(commit_data):
	findings = []

	# scan message
	msg_findings = scan_with_heuristics(commit_data['message'])
	msg_findings += scan_with_llm(commit_data['message'])
	for f in msg_findings:
		f['file'] = 'COMMIT_MESSAGE'
	findings.extend(msg_findings)

	# scan diff
	for diff in commit_data['diff']:
		diff_text = diff.diff.decode('utf-8') if diff.diff else ''
		file_path = diff.a_path or diff.b_path

		heur_findings = scan_with_heuristics(diff_text)
		llm_findings = scan_with_llm(diff_text)

		# combine and dedup (simple: use set of snippets)
		combined = {f['snippet']: f for f in heur_findings + llm_findings}.values()
		for f in combined:
			f['file'] = file_path
			if 'regex' in f['rationale'] and 'high' in f['confidence']:
				f['confidence'] = 'high'
		findings.extend(combined)

	return [{'commit_hash': commit_data['hash'], **f} for f in findings]

'''
#TEST mock a commit_data to test analyze_commit()

from unittest.mock import patch

# Mock git.Diff class
class MockDiff:
    def __init__(self, a_path, b_path, diff):
        self.a_path = a_path
        self.b_path = b_path
        self.diff = diff.encode('utf-8') if diff else None

# Mock ollama.generate function
def mock_ollama_generate(model, prompt):
    # Simulate LLM response for testing
    if 'API_KEY' in prompt:
        return {'response': '[ {"file": "", "snippet": "API_KEY=abc123xyz45678901234567890", "type": "API_KEY", "rationale": "Long alphanumeric string in API key format", "confidence": "high"} ]'}
    return {'response': '[]'}

# Mock commit_data
mock_commit_data = {
    'hash': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
    'message': 'Add API key for testing\nAPI_KEY=abc123xyz45678901234567890',
    'diff': [
        MockDiff(a_path='config.py', b_path='config.py', diff='@@ -1,1 +1,2 @@\n-OLD_KEY=123\n+API_KEY=abc123xyz45678901234567890\n+AWS_KEY=AKIA1234567890ABCDEF'),
        MockDiff(a_path='readme.md', b_path='readme.md', diff='@@ -1,1 +1,1 @@\n-Sample text\n+Sample text with no secrets')
    ]
}

# Test the analyze_commit function
if __name__ == '__main__':
    with patch('ollama.generate', side_effect=mock_ollama_generate):
        results = analyze_commit(mock_commit_data)
        print("Analysis Results:")
        for result in results:
            print(result)
'''





























