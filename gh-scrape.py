import getpass
import json
import os
import sys

import requests
import unicodecsv
from progressbar import *
from requests.auth import HTTPBasicAuth

import json


BASE_URL = 'https://api.github.com{}'

def auth():
    return BASE_URL.format('/authorizations')

def repos(org_name, repo_name):
    return BASE_URL.format('/repos/{}/{}'.format(org_name, repo_name))

def collaborators(org_name, repo_name, access_token):
    return BASE_URL.format('/repos/{}/{}/collaborators?access_token={}'.format(
            org_name,
            repo_name,
            access_token
        )
    )

def stargazers(org_name, repo_name, access_token):
    return BASE_URL.format('/repos/{}/{}/stargazers?access_token={}'.format(
            org_name,
            repo_name,
            access_token
        )
    )

def forkers(org_name, repo_name, access_token):
    return BASE_URL.format('/repos/{}/{}/forks?access_token={}'.format(
            org_name,
            repo_name,
            access_token
        )
    )

def user(login, access_token):
    return BASE_URL.format('/users/{}?access_token={}'.format(login, access_token))

def load_token(token_path):
    try:
        with open(token_path) as f:
            return f.read()
    except IOError:
        return None

def _bad_response(response):
    print response.status_code
    print response.json()
    sys.exit(1)

def _save_token(token_path, token):
    with open(token_path, 'w') as f:
        f.write(token)
    print 'Saved token to {}'.format(token_path)
    return token

def _authorization_exists(response):
    return (
        response.status_code == 422
        and
        response.json()['errors'][0]['code'] == 'already_exists'
    )

def get_github_token(user_name, password, token_path, otp_token=None):
    data = {
        'scopes': [
            'public_repo'
        ],
        'note': 'gh-scrape'
    }
    credentials = HTTPBasicAuth(user_name, password)
    r = requests.post(
        auth(),
        auth=credentials,
        headers={'X-GitHub-OTP': otp_token, 'Content-type': 'application/json'},
        data=json.dumps(data)
    )
    if r.status_code == 401:
        print 'It looks like you are using two-factor authentication.'
        print 'Please input your OTP token below.'
        otp_token = raw_input('OTP token: ')
        return get_github_token(user_name, password, token_path, otp_token=otp_token)
    elif _authorization_exists(r):
        r = requests.get(
            auth(),
            auth=credentials,
            headers={'X-GitHub-OTP': otp_token}
        )
        if r.ok:
            for authorization in r.json():
                if authorization['note'] == 'gh-scrape':
                    return _save_token(token_path, authorization['token'])
        else:
            _bad_response(r)
    else:
        if r.ok:
            return _save_token(token_path, r.json()['token'])
        else:
            _bad_response(r)

def get_repo_from_org(org_name, repo_name):
    r = requests.get(repos(org_name, repo_name))
    if r.ok:
        return r.json()
    else:
        _bad_response(r)

def get_collaborators(repo, org_name, repo_name, access_token):
    r = requests.get(collaborators(org_name, repo_name, access_token))
    if r.ok:
        return [{'github_username': item['login'], 'status': 'collaborator'} for item in r.json()]
    else:
        _bad_response(r)

def get_stargazers(repo, org_name, repo_name, access_token):
    r = requests.get(stargazers(org_name, repo_name, access_token))
    if r.ok:
        return [{'github_username': item['login'], 'status': 'stargazer'} for item in r.json()]
    else:
        _bad_response(r)

def get_forkers(repo, org_name, repo_name, access_token):
    r = requests.get(forkers(org_name, repo_name, access_token))
    if r.ok:
        return [{'github_username': item['owner']['login'], 'status': 'forker'} for item in r.json()]
    else:
        _bad_response(r)

def get_users_stats(users, access_token):
    widgets = ['Progress: ', Percentage(), ' ', Bar(marker='*',left='[',right=']'),
               ' ', ETA(), ' ']
    progress_bar = ProgressBar(widgets=widgets, maxval=500)
    progress_bar.start()

    for idx, user_login in enumerate(users):
        r = requests.get(user(user_login['github_username'], access_token))
        if r.ok:
            data = r.json()

            user_login['public_repos'] = data['public_repos']
            user_login['hireable'] = data.get('hireable')
            user_login['blog'] = data.get('blog')
            user_login['location'] = data.get('location')
            user_login['bio'] = data.get('bio')
            user_login['company'] = data.get('company')
            user_login['url'] = data.get('html_url')
            user_login['name'] = data.get('name')
        else:
            _bad_response(r)

        progress_bar.update(idx)
    progress_bar.finish()
    return users

def write_result_to_csv(csv_path, result):
    print 'Writing file to: {}'.format(csv_path)
    result = sorted(result, key=lambda k: k['name']) 
    with open(csv_path, 'wb') as f:
        w = unicodecsv.DictWriter(f, result[0].keys())
        w.writeheader()
        w.writerows(result)
    print 'All done. Enjoy.'
    return True

def main():
    try:
        token_path = '{}/.gh-scrape-token'.format(os.path.expanduser('~'))
        token = load_token(token_path)
        if not token:
            user_name = raw_input('GitHub username: ')
            password = getpass.getpass('GitHub password: ')
            token = get_github_token(user_name, password, token_path)

        org_name = raw_input('GitHub organization name: ')
        repo_name = raw_input('Repository name: ')

        repo = get_repo_from_org(org_name, repo_name)

        users = (
            get_forkers(repo, org_name, repo_name, token) +
            get_stargazers(repo, org_name, repo_name, token) +
            get_collaborators(repo, org_name, repo_name, token)
        )

        csv_path = '{}/{}:{}-gh-scrape.csv'.format(
            os.getcwd(),
            org_name,
            repo_name
        )

        if write_result_to_csv(csv_path, get_users_stats(users, token)):
            sys.exit(0)
    except KeyboardInterrupt:
        print '\nExiting...'
        sys.exit(0)


if __name__ == '__main__':
    main()
