import os
import git
import tempfile
import re
import ollama
import argparse
import json

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
	Text: {text[:1000]}
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

def main():
	parser = argparse.ArgumentParser(description='Scan Git repo for secrets.')
	parser.add_argument('--repo', required=True, help='Repo path or URL')
	parser.add_argument('--n', type=int, default=5, help='Number of commits')
	parser.add_argument('--out', default='report.json', help='Output JSON file')
	args = parser.parse_args()

	repo = get_repo(args.repo)
	commits = get_last_n_commits(repo, args.n)

	all_findings = []
	for commit in commits:
		all_findings.extend(analyze_commit(commit))

	with open(args.out, 'w') as f:
		json.dump({'findings': all_findings}, f, indent=4)

	print(f'Raport saved to {args.out}')

if __name__ == '__main__':
	main()

