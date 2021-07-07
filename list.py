#!/usr/bin/env python3
import os
import re
import sys
import yaml
import base64
import logging
import argparse
import requests
import urllib.parse

from typing import Iterator


def request_github_api(
        url: str,
        sess: requests.Session,
        accept = 'application/vnd.github.v3+json',
):
    url = urllib.parse.urljoin("https://api.github.com/", url)
    r = sess.get(
        url,
        headers = {'Accept': accept},
    )
    r.raise_for_status()
    return r.json()


def request_all_item_by_page(
        url: str,
        sess: requests.Session,
) -> Iterator[dict]:
    page = 0
    while True:
        page += 1
        contents = request_github_api(url.format(page = page), sess)
        if len(contents) == 0:
            break

        for content in contents:
            yield content


def list_all_user_repo(sess: requests.Session,) -> Iterator[dict]:
    return request_all_item_by_page(
        '/user/repos?page={page}&affiliation=owner,collaborator', sess)


def list_all_org_repo(
        org: str,
        sess: requests.Session,
) -> Iterator[dict]:
    return request_all_item_by_page(f'/orgs/{org}/repos?page={{page}}', sess)


def list_all_orgs(sess: requests.Session,) -> Iterator[dict]:
    return request_all_item_by_page('/user/orgs?page={page}', sess)


def list_all_repos_with_org_regex(
        regex: str,
        sess: requests.Session,
) -> Iterator[dict]:
    for org in list_all_orgs(sess):
        org_name = org.get('login', '')
        logging.debug(f'Get Org: {org_name}')
        if re.match(regex, org_name):
            for repo in list_all_org_repo(org_name, sess):
                yield repo


def list_actions_files_of_repo(
        repo: str,
        branch: str,
        sess: requests.Session,
) -> Iterator[dict]:
    logging.debug(f'Start list actions files of {repo}, {branch}')

    commits = request_github_api(f'/repos/{repo}/commits/{branch}', sess)
    logging.debug(f'Get Commit: {commits["commit"]}')
    root_tree = request_github_api(commits['commit']['tree']['url'], sess)
    logging.debug(f'Get Root Tree: {root_tree}')

    for github_folder in root_tree['tree']:
        if github_folder['path'] == '.github':
            github_tree = request_github_api(github_folder['url'], sess)
            logging.debug(f'Get Github Tree: {github_tree}')

            for workflows_folder in github_tree['tree']:
                if workflows_folder['path'] == 'workflows':
                    workflows_tree = request_github_api(workflows_folder['url'],
                                                        sess)
                    logging.debug(f'Get Wrokflows Tree: {workflows_tree}')

                    for workflows_file in workflows_tree['tree']:
                        if workflows_file.get('type', '') != 'blob':
                            logging.debug(
                                f'[Skip] Non blob in workflows: {workflows_file}'
                            )
                        else:
                            logging.debug(
                                f'[Actions] Get yaml: {workflows_file["path"]}')
                            yield request_github_api(workflows_file['url'],
                                                     sess)


def check_schedule_for_yaml(blob: dict, repo: str):
    try:
        if blob['encoding'] == 'base64':
            content_str = base64.b64decode(blob['content'].encode())
        else:
            logging.error(f'Unknown encoding for blob: {blob["encoding"]}')
            return

        content = yaml.load(content_str, Loader = yaml.BaseLoader)
        if 'schedule' in content.get('on', dict()):
            logging.info(f'Got schedule action of {repo}')
    except:
        logging.exception(f'[Fatal] Dump action yaml failed of {repo}')


def arg_parse(args) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--token', default = os.environ.get('GITHUB_TOKEN'))
    parser.add_argument('-o', '--org', default = os.environ.get('ORG'))
    parser.add_argument(
        '-x',
        '--proxy',
        default = os.environ.get('HTTPS_PROXY') or
        os.environ.get('https_proxy'))
    parser.add_argument('--debug', action = 'store_true')

    return parser.parse_args(args)


def main():
    args = arg_parse(sys.argv[1:])
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    with requests.session() as sess:
        if args.proxy:
            sess.proxies = {
                'http': args.proxy,
                'https': args.proxy,
            }
        token = f':{args.token}'.encode()
        sess.headers[
            'Authorization'] = f'Basic {base64.b64encode(token).decode()}'

        for repo in list_all_user_repo(sess):
            try:
                for blob in list_actions_files_of_repo(
                        repo['full_name'],
                        repo['default_branch'],
                        sess,
                ):
                    check_schedule_for_yaml(blob, repo['full_name'])
            except:
                logging.exception('Unable to list blob of repo: {0}'.format(
                    repo['full_name']))

        if args.org:
            for repo in list_all_repos_with_org_regex(args.org, sess):
                try:
                    for blob in list_actions_files_of_repo(
                            repo['full_name'],
                            repo['default_branch'],
                            sess,
                    ):
                        check_schedule_for_yaml(blob, repo['full_name'])
                except:
                    logging.exception('Unable to list blob of repo: {0}'.format(
                        repo['full_name']))


if __name__ == "__main__":
    logging.basicConfig(
        level = logging.INFO,
        format = '%(asctime)s %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %X',
    )
    main()
