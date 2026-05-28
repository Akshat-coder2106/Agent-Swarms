"""
GitHub App Integration.

Handles GitHub App authentication using private keys,
generates installation tokens, and performs PR operations.
"""
import time
import urllib.parse

import httpx
import jwt

from ..sentinel.models import AuditSession, PatchProposal


class GitHubAppError(Exception):
    pass


class GitHubAppClient:
    def __init__(self, app_id: str, private_key: str):
        self.app_id = app_id
        self.private_key = private_key
        self._installation_tokens: dict[str, tuple[str, int]] = {}

    def _generate_jwt(self) -> str:
        """Generate a JWT for authenticating as the GitHub App."""
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def get_installation_token(self, installation_id: str) -> str:
        """Fetch or generate a short-lived installation token."""
        # Check cache
        if installation_id in self._installation_tokens:
            token, exp = self._installation_tokens[installation_id]
            if time.time() < exp - 60:
                return token

        # Generate new token
        app_jwt = self._generate_jwt()
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://api.github.com/app/installations/{installation_id}/access_tokens",
                headers=headers
            )
            if resp.status_code != 201:
                raise GitHubAppError(f"Failed to get installation token: {resp.text}")
                
            data = resp.json()
            token = data["token"]
            # Expiration is in ISO8601, simplified cache here
            exp = int(time.time()) + 3600
            self._installation_tokens[installation_id] = (token, exp)
            return token

    async def create_remediation_pr(
        self,
        installation_id: str,
        session: AuditSession,
        patch: PatchProposal
    ) -> str:
        """Forks, commits, and opens a PR using the GitHub App token."""
        token = await self.get_installation_token(installation_id)
        
        # The logic here remains similar to the original github_integration.py
        # but using the App's token and identity.
        if not session.repo_path.startswith("http"):
            return "https://github.com/demo-user/local-repo/pull/1"

        parsed = urllib.parse.urlparse(session.repo_path)
        path_parts = parsed.path.strip("/").split("/")
        owner, repo = path_parts[0], path_parts[1].replace(".git", "")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            # Fork (App might push to a new branch on the same repo instead of forking,
            # since Apps are installed on the repo directly)
            
            # 1. Get default branch
            ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/main"
            ref_resp = await client.get(ref_url, headers=headers)
            if ref_resp.status_code != 200:
                ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/master"
                ref_resp = await client.get(ref_url, headers=headers)
                
            if ref_resp.status_code != 200:
                raise GitHubAppError("Could not find default branch.")
                
            base_sha = ref_resp.json()["object"]["sha"]
            branch_name = f"sentinel-patch-{patch.patch_id[:8]}"

            # 2. Create new branch directly in the same repo
            branch_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
            )
            if branch_resp.status_code != 201:
                raise GitHubAppError(f"Failed to create branch: {branch_resp.text}")

            # 3. Create Tree
            tree_items = []
            for file_patch in patch.files:
                tree_items.append({
                    "path": file_patch.file_path,
                    "mode": "100644",
                    "type": "blob",
                    "content": file_patch.patched
                })
                
            tree_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees",
                headers=headers,
                json={"base_tree": base_sha, "tree": tree_items}
            )
            new_tree_sha = tree_resp.json()["sha"]

            # 4. Create Commit
            commit_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/git/commits",
                headers=headers,
                json={
                    "message": f"Security patch: {patch.rationale[:50]}...",
                    "tree": new_tree_sha,
                    "parents": [base_sha]
                }
            )
            new_commit_sha = commit_resp.json()["sha"]

            # 5. Update Ref
            await client.patch(
                f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch_name}",
                headers=headers,
                json={"sha": new_commit_sha}
            )
            
            # 6. Create PR
            pr_body = (
                f"## Project Sentinel - Security Remediation\n\n"
                f"This PR was auto-generated by Sentinel after an autonomous audit.\n\n"
                f"### Patch Details\n"
                f"**Rationale:** {patch.rationale}\n"
                f"**Risk Level:** {patch.risk}\n\n"
            )
            
            pr_resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                headers=headers,
                json={
                    "title": f"Security Fix: {patch.rationale[:50]}",
                    "body": pr_body,
                    "head": branch_name,
                    "base": ref_url.split("/")[-1],
                    "draft": False
                }
            )
            if pr_resp.status_code != 201:
                raise GitHubAppError(f"Failed to create PR: {pr_resp.text}")

            return pr_resp.json()["html_url"]
