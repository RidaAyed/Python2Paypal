# -*- coding: utf-8 -*-

"""
Test suite for tsv_automation.py
"""

from requests_oauthlib import OAuth2Session
from src import tsv_automation as src
import json
import oauthlib
import os
import pytest
import vcr

def cmp_dict(dict1, dict2):
  return json.dumps(dict1, sort_keys = True) == json.dumps(dict2, sort_keys = True)

def assert_complain(capsys, complain_msg, method, *args):
  with pytest.raises(SystemExit) as module_exit:
    method(*args)
  assert module_exit.type == SystemExit
  assert module_exit.value.code == 1
  captured = capsys.readouterr()
  assert captured.out == ""
  assert captured.err == "Error: " + complain_msg + ". Quitting.\n"

def test_complain(capsys):
  complain_msg = "X"
  assert_complain(capsys, complain_msg, src.complain, "X")

def test_validate_timestamp(capsys):
  date = "1998-12-01"
  datetime = "1998-12-01T12:33:59"
  assert src.validate_timestamp(datetime, "from-date") == datetime
  assert src.validate_timestamp(date, "from-date") == date + "T00:00:00"
  assert src.validate_timestamp(date, "to-date") == date + "T23:59:59"

  ts_type = "x-date"
  complain_msg = "Cannot read the timestamp type: x-date".format(ts_type)
  assert_complain(capsys, complain_msg, src.validate_timestamp, date, ts_type)

  ts_type = "from-date"
  date = date + "x"
  complain_msg = "Timestamp --{}={} doesn't match the expected pattern YYYY-MM-HH[THH:MM:SS]".format(ts_type, date)
  assert_complain(capsys, complain_msg, src.validate_timestamp, date, ts_type)

def test_validate_params():
  params = {'--from-date': '2016-07-01',
           '--help': False,
           '--to-date': '2018-07-02'}
  expected_params = {'--from-date': '2016-07-01T00:00:00',
                    '--help': False,
                    '--to-date': '2018-07-02T23:59:59'}
  assert cmp_dict(src.validate_params(params), expected_params)

def test_load_secrets(capsys):
  expected = {
    'client_id': os.environ['CLIENT_ID'],
    'client_secret': os.environ['CLIENT_SECRET']
  }

  result = src.load_secrets()
  assert cmp_dict(expected, result)

  result = src.load_secrets(None)
  assert cmp_dict(expected, result)

  expected = {
    'client_id': 'test_id',
    'client_secret': 'test_secret'
  }
  result = src.load_secrets("test_secrets.yml")
  assert cmp_dict(expected, result)

  complain_msg = "File not found: missing_file.yml"
  assert_complain(capsys, complain_msg, src.load_secrets, "missing_file.yml")

def test_check_status_code(capsys):
  code = 200
  assert src.check_status_code(code) == None

  code = 201
  complain_msg = "Received unexpected status code " + str(code) + " != 200"
  assert_complain(capsys, complain_msg, src.check_status_code, code)

@vcr.use_cassette('vcr_cassettes/auth_secrets.yaml', filter_headers=['authorization'], filter_post_data_parameters=['client_id', 'client_secret'])
def test_obtain_auth_secrets(capsys):
  secrets = src.load_secrets("secrets.yml")
  token = src.obtain_auth_token(secrets)
  assert type(token) is oauthlib.oauth2.rfc6749.tokens.OAuth2Token

  secrets = {
    'client_id': 'broken_id',
    'client_secret': 'broken_secret'
  }
  complain_msg = 'Unable to obtain authentication token due to exception: (invalid_client) Client Authentication failed'
  assert_complain(capsys, complain_msg, src.obtain_auth_token, secrets)

@vcr.use_cassette('vcr_cassettes/get_trx_list.yaml', filter_headers=['authorization'], filter_post_data_parameters=['client_id', 'client_secret'])
def test_get_transactions(capsys):
  secrets = src.load_secrets()
  token = src.obtain_auth_token(secrets)
  session = OAuth2Session(secrets['client_id'], token=token)

  complain_msg = 'The query can span across 3 years maximum'
  assert_complain(capsys, complain_msg, src.get_transactions, session, '2010-07-01T12:12:12', '2018-07-02T11:11:11')
  complain_msg = 'The historical data is available only from July 2016'
  assert_complain(capsys, complain_msg, src.get_transactions, session, '2010-07-01T01:01:01', '2010-08-01T13:13:13')

  arguments = {'--from-date': '2016-12-01T00:00:00',
              '--to-date': '2018-12-27T23:59:59'}
  trx = src.get_transactions(session, arguments['--from-date'], arguments['--to-date'])
  assert type(trx) is dict
  assert len(trx) == 3

def test_extract_value():
  dataset = {'level1': 
                  {'level2': 'value'}
            }
  assert src.extract_value(dataset, ['level1', 'level2']) == 'value'
  assert src.extract_value(dataset, 'missing') == ''

def test_merge_transactions(capsys):
  base = ['', 'b', 'c', 'd', 'CHF', '5']
  new = ['a', '', 'c', 'd', 'EUR', '4', 'g']
  result = src.merge_transactions(base, new)
  
  # Test filling-in the blanks while merging the transactions
  assert result[0] == 'a'
  assert result[1] == 'b'
  assert result[6] == 'g'
  assert len(result) == 7

  # Test discarding the transactions in non-base-currency
  assert float(result[5]) == 4.0

  base = ['a', 'b', 'c', 'd', 'EUR', '4.0']
  new = ['a', 'b', 'c', 'd', 'EUR', '-4.0']
  result = src.merge_transactions(base, new)

  # Test handling debit and credit transactions
  assert result[5] == '-4.0'

  base = ['a', 'b', 'c', 'd', 'EUR', '9.0']
  new = ['a', 'b', 'c', 'd', 'EUR', '-4.0']
  result = src.merge_transactions(base, new)
  captured = capsys.readouterr()
  assert captured.out == 'WARN: Transaction has been ignored\n\n'
  assert captured.err == "WARN: Unexpected situation occurred while merging transactions\n['a', 'b', 'c', 'd', 'EUR', '9.0']\n['a', 'b', 'c', 'd', 'EUR', '-4.0']\n\n"

def test_combine_transactions():
    trx = {'0': ['2018-12-22', '00:00:01', 'c', 'd', 'CHF', '5'],
           '1': ['2018-12-22', '00:00:01', '', 'd', 'EUR', '4'],
           '2': ['2018-12-22', '00:00:02', 'c', '', 'CHF', '50'],
           '3': ['2018-12-22', '00:00:02', 'c', 'd', 'EUR', '40']
           }
    result = src.combine_transactions(trx)
    
    # Test the result
    assert len(result) == 2
    assert result['2018-12-22T00:00:01'][2] == 'c'
    assert result['2018-12-22T00:00:02'][5] == '40'
    assert set(result.keys()) == {'2018-12-22T00:00:01', '2018-12-22T00:00:02'}

def test_store_tsv(tmpdir):
    data = {'0': ['a', 'b'],
            '1': ['c', 'd']
            }
    filename = tmpdir.join('out.tsv')
    src.store_tsv(str(filename), data)
    print(filename.read())
    # Test if the content of the file written is the correct one
    assert filename.read() == 'a\tb\nc\td\n'
