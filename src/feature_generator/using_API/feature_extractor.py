import threading
import csv
import re
import urllib
import urllib2
import pandas as pd
import pygeoip
import whois  # pip install python-whois
import tldextract
import pythonwhois

from datetime import datetime
from urlparse import urlparse
from xml.dom import minidom

features = []
nf = -100


def find_ele_with_attribute(dom, ele, attribute):
    for subelement in dom.getElementsByTagName(ele):
        if subelement.hasAttribute(attribute):
            return subelement.attributes[attribute].value
    return nf


def sitepopularity(host):
    xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + host
    try:
        xml = urllib2.urlopen(xmlpath)
        dom = minidom.parse(xml)
        host_rank = find_ele_with_attribute(dom, 'REACH', 'RANK')
        country_rank = find_ele_with_attribute(dom, 'COUNTRY', 'RANK')
        return [host_rank, country_rank]

    except:
        return [nf, nf]


def tokenise(url):
    token_word = re.split('\W+', url)
    no_ele = sum_len = largest = 0
    for ele in token_word:
        l = len(ele)
        sum_len += l
        if l > 0:  ## for empty element exclusion in average length
            no_ele += 1
        if largest < l:
            largest = l
    try:
        return [float(sum_len) / no_ele, no_ele, largest]
    except:
        return [nf, nf, nf]


def check_ipaddress(tokens_words):
    cnt = 0
    for ele in tokens_words:
        if unicode(ele).isnumeric():
            cnt += 1
        else:
            if cnt >= 4:
                return 1
            else:
                cnt = 0
    if cnt >= 4:
        return 1
    return 0


def getasn(host):
    try:
        g = pygeoip.GeoIP("C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\datasets\\GeoIPASNum.dat")
        asn = int(g.org_by_name(host).split()[0][2:])
        return asn
    except:
        return nf


def safebrowsing(url):
    api_key = "ABQIAAAA8C6Tfr7tocAe04vXo5uYqRTEYoRzLFR0-nQ3fRl5qJUqcubbrw"
    name = "URL_check"
    ver = "1.0"
    req = {"client": name, "apikey": api_key, "appver": ver, "pver": "3.0", "url": url}

    try:
        params = urllib.urlencode(req)
        req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?" + params
        res = urllib2.urlopen(req_url)
        return res.code
    except:
        return nf


def whoisinfo(host):
    try:
        domain = pythonwhois.get_whois(host)
        cdate = nf
        for lines in domain['raw'][0].split('\n'):
            if 'Creation Date' in lines:
                cdate = datetime.strptime(lines.split(': ')[1].split('T')[0], '%Y-%m-%d')
                break
            elif 'Created On' in lines:
                try:
                    cdate = datetime.strptime(lines.split(':')[1].split(' ')[0], '%d-%b-%Y')
                except:
                    cdate = datetime.strptime(lines.split(':')[1].strip(), '%Y-%m-%d')
                    pass
                break
            elif 'Registration Time' in lines:
                cdate = datetime.strptime(lines.split(': ')[1].split(' ')[0], '%Y-%m-%d')
                break
            elif 'created' in lines:
                if 'T' in lines:
                    cdate = datetime.strptime(lines.split(':')[1].strip().split('T')[0], '%Y-%m-%d')
                elif '/' in lines:
                    cdate = datetime.strptime(lines.split(':')[1].strip(), '%d/%m/%Y')
                elif '-' in lines:
                    cdate = datetime.strptime(lines.split(':')[1].strip(), '%Y-%m-%d')
                elif '.' in lines:
                    cdate = datetime.strptime(lines.split(':')[1].strip().split(' ')[0], '%Y.%m.%d')
                else:
                    date = lines.split(':')[1].strip()
                    year = str(date[0:4])
                    month = str(date[4:6])
                    day = str(date[6:8])
                    date = str(year + '-' + month + '-' + day)
                    cdate = datetime.strptime(date, '%Y-%m-%d')
                break
            elif 'Registered on' in lines:
                if 'before' in lines:
                    cdate = datetime.strptime(
                        str(lines).split(': ')[1].strip().replace('before Aug-1996', '01-08-1996'), '%d-%m-%Y')
                else:
                    cdate = datetime.strptime(lines.split(': ')[1].strip(), '%d-%b-%Y')
                break
            elif '[Connected Date]' in lines:
                cdate = datetime.strptime(lines.split(']')[1].strip(), '%Y/%m/%d')
                break
            elif 'Created' in lines:
                cdate = datetime.strptime(lines.split(':')[1].strip().split(' ')[0], '%Y-%m-%d')
                break
            elif 'Domain Name Commencement Date' in lines:
                cdate = datetime.strptime(lines.split(': ')[1].strip(), '%d-%m-%Y')
                break
            elif 'Changed' in lines:
                cdate = datetime.strptime(lines.split(':')[1].strip().split('T')[0], '%Y-%m-%d')
                break
        current = datetime.today()
        if cdate != nf:
            months = (current.year - cdate.year) * 12 + current.month - cdate.month
            return months
        else:
            return nf
    except:
        return nf


def feature_ext(url, label):
    feature = {}
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    tokens_words = re.split('\W+', url)
    host = domain + '.' + suffix if domain != '' else suffix
    # host = obj.netloc
    path = urlparse(url).path

    feature['url'] = url
    feature['host'] = host
    feature['path'] = path
    feature['label'] = label
    feature['url_len'] = len(url)
    feature['host_len'] = len(host)
    feature['no_of_dots'] = url.count('.')
    feature['host_rank'], feature['country_rank'] = sitepopularity(host)
    feature['url_avg_token_len'], feature['url_token_count'], feature['url_largest_token'] = tokenise(url)
    feature['host_avg_token_len'], feature['host_token_count'], feature['host_largest_token'] = tokenise(host)
    feature['path_avg_token_len'], feature['path_token_count'], feature['path_largest_token'] = tokenise(path)
    feature['ipaddress_presence'] = check_ipaddress(tokens_words)
    feature['asn_no'] = getasn(host)
    feature['safebrowsing'] = safebrowsing(url)
    feature['domain_age'] = 0 if feature['ipaddress_presence'] == 1 else whoisinfo(host)
    # feature['in_dynamic_dns'] = whoisinfo(host)
    # feature['shortened_url'} = is_shortened(url)
    # feature['web_content'] = get_web_features(url)

    return features.append(feature)


def result_writer(features, outfile):
    keys = features[0].keys()
    with open(outfile, 'wb') as of:
        dict_writer = csv.DictWriter(of, keys)
        dict_writer.writeheader()
        dict_writer.writerows(features)


def test(url):
    feature = {}
    obj1 = tldextract.extract(url)
    host = obj1.domain + '.' + obj1.suffix if obj1.domain != '' else obj1.suffix

    feature['url'] = url
    feature['host'] = host
    feature['domain_age'] = whoisinfo(host)
    features.append(feature)


if __name__ == '__main__':
    s = tldextract.extract('http://bozkir.com')
    print s
    host = s.domain + '.' + s.suffix if s.domain != '' else s.suffix
    rec = whois.whois(host)
    print rec
    creation_date = rec['creation_date'] if 'creation_date' in rec else rec['created']
    if type(creation_date) == list:
        creation = creation_date[0] if type(creation_date[0]) == datetime else datetime.strptime(creation_date[1], '%Y%m%d')
    elif type(creation_date) == datetime:
        creation = creation_date
    elif type(creation_date) == unicode:
        creation = datetime.strptime(str(creation_date).replace('before Aug-1996', '1-8-1996'), '%d-%m-%Y')
    else:
        creation = 'NA'
    print creation

    # # Generate features from file.
    # # filePath = 'C:\\Users\\Nilesh Shaikh\\Desktop\\domains.csv'
    # filePath = 'C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\datasets\\malicious_url\\data_for_api_model.csv'
    # urls = pd.read_csv(filePath, header=None)
    # df = urls.sample(frac=1)  # random split data
    #
    # threads = []
    # for index, row in df.iterrows():
    #     # thread = threading.Thread(target=test, args=(row[0],))
    #     thread = threading.Thread(target=feature_ext, args=(row[0], row[1],))
    #     threads.append(thread)
    #     thread.start()
    #
    # # wait to complete all threads
    # for thread in threads:
    #     thread.join()
    #
    # result_writer(features, "C:\\Users\\Nilesh Shaikh\\Desktop\\Peerlox\\feature_set\\mal_url.csv")
