import hashlib
import json
import os
import shutil
import tempfile
import tarfile
import zipfile
import io
try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

import requests

from lxml import html


def download_latest_jdk_version(url, dl_dir):
    content = requests.get(url).content.decode('utf-8')
    doc = html.fromstring(content)
    files_to_download = {}
    for node in doc.xpath('.//script'):
        if not node.text:
            continue
        for line in node.text.split('\n'):
            if 'downloads[' in line and '"title"' in line:
                json_part = line.split('=')[-1].strip().strip(';')
                download_item = json.loads(json_part)
                if 'demos' in download_item['filepath'].lower():
                    continue
                if not download_item['title'] in {'Linux x86', 'Linux x64'}:
                    continue
                if not download_item['filepath'].endswith('tar.gz'):
                    continue
                files_to_download[download_item['title']] = download_item
    session = requests.session()
    for key, val in files_to_download.items():
        fname = val['filepath'].replace('\\', '_').split('/')[-1]
        base_loc = dl_dir
        dl_loc = os.path.join(base_loc, fname)
        if not os.path.abspath(dl_loc).startswith(base_loc):
            raise ValueError('No path traversal please. %s' % dl_loc)
        print('downloading %s to %s' % (val['filepath'], dl_loc))
        resp = session.get(
            val['filepath'], cookies={
                "oraclelicense": "accept-securebackup-cookie"})
        with open(dl_loc, 'wb') as f:
            f.write(resp.content)


def sha_256_sum_file(f_obj):
    hasher = hashlib.sha256()
    for line in f_obj:
        hasher.update(line)
    return hasher.hexdigest()


def verify_downloaded_jdk(dl_dir):
    base_digest_url = ('https://www.oracle.com/webfolder/s/digest/'
                       '%schecksum.html')
    for f in os.listdir(dl_dir):
        fname = os.path.join(dl_dir, f)
        if os.path.isfile(fname) and fname.endswith('.tar.gz'):
            v_hashes = {}
            verify_url = base_digest_url % quote_plus(fname.split('-')[1])
            resp = requests.get(verify_url).content.decode('utf-8')
            doc = html.fromstring(resp)
            for node in doc.xpath('.//tr'):
                data = [td for td in node.findall('td')]
                if len(data) != 2:
                    continue
                v_file = data[0].text.strip()
                v_hash = data[1].text.split(' ')[2]
                v_hashes[v_file] = v_hash
            actual_file_hash = ''
            with open(fname, 'rb') as f_file:
                actual_file_hash = sha_256_sum_file(f_file)
            if actual_file_hash != v_hashes[f]:
                raise ValueError(
                    'Hash of %s does not match %s (was %s)' %
                    (fname, v_hashes[f], actual_file_hash))
            print('Verified the hash of %s using %s as %s' %
                  (fname, verify_url, actual_file_hash))


def download_unlimited_jce_policy(jce_fname):
    session = requests.session()
    resp = session.get(
        'http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip',
        cookies={"oraclelicense": "accept-securebackup-cookie"}, stream=True)
    with open(jce_fname, 'wb') as f:
        shutil.copyfileobj(resp.raw, f)


def verify_url_jce_policy(fname, jce_file):
    expected_hash = ('f3020a3922efd6626c2fff45695d527f34a8020e938a4'
                     '9292561f18ad1320b59')
    actual_file_hash = sha_256_sum_file(jce_file)
    if actual_file_hash != expected_hash:
        raise ValueError('Hash of %s does not match %s (was %s)' %
                         fname, expected_hash, actual_file_hash)


def patch_java_crypto_policy_files(dl_dir, result_dir):
    jce_zip_path = os.path.join(dl_dir, 'jce_policy-8.zip')
    jce_files = {}
    with zipfile.ZipFile(jce_zip_path, 'r') as z_file:
        for name in z_file.namelist():
            if name.endswith('/local_policy.jar') or name.endswith(
                    '/US_export_policy.jar'):
                bytesIO = io.BytesIO(z_file.read(name))
                jce_files[os.path.basename(name)] = bytesIO
    if {'local_policy.jar', 'US_export_policy.jar'} != set(jce_files.keys()):
        raise ValueError('The JCE does not contain the expected content')
    for f in os.listdir(dl_dir):
        fname = os.path.join(dl_dir, f)
        if os.path.isfile(fname) and fname.endswith('.tar.gz'):
            output_tar = tarfile.open(
                os.path.join(result_dir, f), mode='w:gz')
            print('Going to patch', fname)
            with tarfile.open(fname, mode='r:gz') as tar:
                for tar_info in tar.getmembers():
                    tar_f_obj = tar.extractfile(tar_info)
                    if os.path.basename(tar_info.name) in jce_files.keys():
                        tar_f_obj = jce_files[os.path.basename(tar_info.name)]
                        tar_f_obj.seek(0, os.SEEK_END)
                        size = tar_f_obj.tell()
                        tar_info.size = size
                        tar_f_obj.seek(0)
                        print('patching', tar_info.name)
                    output_tar.addfile(tar_info, tar_f_obj)
            output_tar.close()


def main():
    latest_version_url = ('https://www.oracle.com/technetwork/java/javase/'
                          'downloads/jdk8-downloads-2133151.html')
    dl_dir = os.path.abspath('downloads')
    result_dir = os.path.join(dl_dir, 'patched')
    os.makedirs(result_dir)
    download_latest_jdk_version(latest_version_url, dl_dir)
    verify_downloaded_jdk(dl_dir)
    jce_fname = os.path.join(dl_dir, 'jce_policy-8.zip')
    download_unlimited_jce_policy(jce_fname)
    with open(jce_fname, 'rb') as jce_file:
        verify_url_jce_policy(jce_fname, jce_file)
    patch_java_crypto_policy_files(dl_dir, result_dir)
    print('You can find patched jdk files in', result_dir)


if __name__=='__main__':
    main()
