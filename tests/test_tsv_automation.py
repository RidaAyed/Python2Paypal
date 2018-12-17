# -*- coding: utf-8 -*-

"""
Test suite for tsv_automation.py
"""

from src import tsv_automation as src
import json
import pytest

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
  assert json.dumps(src.validate_params(params), sort_keys = True) == json.dumps(expected_params, sort_keys = True)

def test_check_status_code(capsys):
  code = 200
  assert src.check_status_code(code) == None

  code = 201
  complain_msg = "Received unexpected status code " + str(code) + " != 200"
  assert_complain(capsys, complain_msg, src.check_status_code, code)
