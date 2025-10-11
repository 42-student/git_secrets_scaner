import git
import tempfile
import os

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

