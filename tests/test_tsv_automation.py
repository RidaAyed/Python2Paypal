# -*- coding: utf-8 -*-

"""
Test suite for tsv_automation.py
"""

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

@vcr.use_cassette('vcr_cassettes/auth_secrets.yaml')
def test_obtain_auth_secrets(capsys):
  secrets = src.load_secrets()
  token = src.obtain_auth_token(secrets)
  assert type(token) is oauthlib.oauth2.rfc6749.tokens.OAuth2Token

  secrets = {
    'client_id': 'broken_id',
    'client_secret': 'broken_secret'
  }
  token = src.obtain_auth_token(secrets)
  assert type(token) is oauthlib.oauth2.rfc6749.tokens.OAuth2Token
