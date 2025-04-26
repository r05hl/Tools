import requests

def get_email_from_commits(username):
    # Step 1: Get list of public repositories
    repos_url = f"https://api.github.com/users/{username}/repos?sort=updated"
    response = requests.get(repos_url)
    if response.status_code != 200:
        print("Could not fetch repositories.")
        return None

    repos = response.json()
    if not repos:
        print("No public repositories found.")
        return None

    # Step 2: Iterate through repositories
    for repo in repos:
        repo_name = repo['name']
        print(f"Checking repository: {repo_name}")

        # Step 3: Get the commits for the repo
        commits_url = f"https://api.github.com/repos/{username}/{repo_name}/commits"
        response = requests.get(commits_url)
        if response.status_code != 200:
            print(f"Could not fetch commits for repository: {repo_name}")
            continue

        commits = response.json()
        for commit in commits:
            try:
                email = commit['commit']['author']['email']
                if email and not email.endswith("@users.noreply.github.com"):
                    return email
            except KeyError:
                continue

    print("No real email found in commit metadata.")
    return None

if __name__ == "__main__":
  #Here replace with actual username and make sure that it has independent commits on public repos not just forks
    username = "username"
    email = get_email_from_commits(username)
    if email:
        print(f"✅ Found email: {email}")
    else:
        print("❌ Could not retrieve email from public commits.")
