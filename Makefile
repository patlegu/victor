.PHONY: help push push-github push-gitlab sync-gitlab

GITHUB_BRANCH := main
GITLAB_BRANCH := gitlab-main

help:
	@echo "Cibles disponibles :"
	@echo "  make push          — pousse main → GitHub ET sync gitlab-main → GitLab"
	@echo "  make push-github   — pousse main → GitHub uniquement"
	@echo "  make push-gitlab   — sync gitlab-main depuis main, puis pousse → GitLab"
	@echo "  make sync-gitlab   — merge main dans gitlab-main (sans push)"

## Pousse les deux remotes dans le bon ordre
push: push-github push-gitlab

## GitHub — branche main uniquement (sans training/)
push-github:
	@echo "→ GitHub : push $(GITHUB_BRANCH)"
	git push github $(GITHUB_BRANCH)

## GitLab — merge main dans gitlab-main, puis push
push-gitlab: sync-gitlab
	@echo "→ GitLab : push $(GITLAB_BRANCH)"
	git push gitlab $(GITLAB_BRANCH):main

## Merge main dans gitlab-main (le merge driver ours garde le .gitignore de gitlab-main)
sync-gitlab:
	@current=$$(git rev-parse --abbrev-ref HEAD); \
	echo "→ Merge $(GITHUB_BRANCH) dans $(GITLAB_BRANCH)"; \
	git checkout $(GITLAB_BRANCH) && \
	git merge $(GITHUB_BRANCH) --no-edit && \
	git checkout $$current
