# -*- coding: utf-8 -*-

"""
Automate PayPal authentication and download of the TSV file with the transactional data

Pre-requisites:
    1. Create Business Sandbox Account (you might need to create standard account, then upgrade to business)
       https://www.sandbox.paypal.com/signup/create

    2. Link the Sandbox account with the Developer account
       https://developer.paypal.com/developer/accounts/

    3. Create PayPal App
       https://developer.paypal.com/developer/applications/create
       - Save the Client ID and the Secret string (see the switch in the top-right corner for sandbox and live environments)
       - Update the python code with the client_id and client_secret values
       - Enable "Transaction Search" in the settings

    4. Define your 'base currency' in the script constants. This is needed to filter-out the conversion transactions
       when paying in the foreign currency.

    5. The script then queries and processes the data from the PayPal API
       - First it gets the list of the transactions from between the individual timestamps
       - For each transaction it queries for full details
       - Writes the selected fields into the tsv file

Usage:
  tsv_automation.py --from-date=<from_date> --to-date=<to_date>
  tsv_automation.py -h | --help

Options:
  -h --help                 Show this screen.
  --from-date=<from_date>   
  --to-date=<to_date>       Both <from_date> and <to_date> timestamp values take the following timestamp format:
                            YYYY-MM-DDTHH:MM:SS, where the time section can be ommitted ('THH:MM:SS') and is
                            assumed as T00:00:00 in case of the <from-date> and T23:59:59 in case of the
                            <to-date>.

"""

from datetime import datetime, timedelta, timezone
from docopt import docopt
from oauthlib.oauth2 import BackendApplicationClient
from progress.bar import ChargingBar
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import csv
import json
import logging
import os
import re
import requests
import sys
import yaml

import traceback
import pprint

FILENAME = 'trx.tsv'

# Use in format (+|-)HHMM
# Currently only -HHMM works, see https://github.com/paypal/PayPal-REST-API-issues/issues/211
TIMEZONE_OFFSET = '-0000'
BASE_CURRENCY = 'EUR'

# URL = "https://api.paypal.com"
URL = "https://api.sandbox.paypal.com"
TOKEN_URL = URL + "/v1/oauth2/token"
TRX_URL = URL + "/v1/reporting/transactions"

def complain(text):
    """
    Method that prints the message on STDERR and exits the script.

    :param text: Message to be printed
    :type text: string
    """
    print("Error: " + text + ". Quitting.", file=sys.stderr)
    sys.exit(1)

def validate_timestamp(string, ts_type):
    """
    Metod used for the timestamp validation. In case time fraction is missing, add it automatically
    by looking at the ts_type (from-date|to-date).

    :param string: timestamp to be verified
    :type string: string, expected YYYY-MM-DD[THH:MM:SS]
    :param ts_type: type of timestamp
    :type ts_type: string, expected (from-date|to-date)
    :return: validated timestamp
    :rtype: string, format YYYY-MM-DDTHH:MM:SS
    """
    date_regex = '[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])'
    date_time_regex = date_regex + '[T,t]([0-1][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)'
    date_pattern = re.compile('^' + date_regex + '$')
    date_time_pattern = re.compile('^' + date_time_regex + '$')

    if date_time_pattern.match(string):
        # Timestamp check OK
        pass
    elif date_pattern.match(string):
        # Timestamps without time were received, time needs to be added
        if ts_type == 'from-date':
            string = string + 'T00:00:00'
        elif ts_type == 'to-date':
            string = string + 'T23:59:59'
        else:
            complain("Cannot read the timestamp type: {}".format(ts_type))
    else:
        complain("Timestamp --{}={} doesn't match the expected pattern YYYY-MM-HH[THH:MM:SS]".format(ts_type, string))

    return string


def validate_params(params):
    """
    Method that takes care of the input parameter validation. Stop the execution in case of a validation error.

    :param params: Arguments to be validated
    :type params: dict (key is the argument name, value is it's value)
    """
    if '--from-date' not in params.keys():
        complain("--from-date is a mandatory parameter")
    if '--to-date' not in params.keys():
        complain("--to-date is a mandatory parameter")

    params['--from-date'] = validate_timestamp(params['--from-date'], 'from-date')
    params['--to-date'] = validate_timestamp(params['--to-date'], 'to-date')

    return params

def load_secrets(secrets_file=None):
    """
    Method for loading the secrets from the environment or from the secrets file

    :param secrets_file: file containing the secrets
    :type secrets_file: string
    :return: loaded secrets
    :rtype: dict
    """
    if secrets_file == None:
      data = {}
      data['client_id'] = os.environ['CLIENT_ID']
      data['client_secret'] = os.environ['CLIENT_SECRET']
    else:
      try:
          with open(secrets_file, 'r') as stream:
              try:
                  data = (yaml.load(stream))
              except Exception as exc:
                  complain("Exception occurred while reading " + secrets_file + ": " + str(exc))
      except FileNotFoundError as fnf:
          complain("File not found: " + secrets_file)

      if "client_id" not in data.keys():
          complain("Missing client_id in " + secrets_file)
      if "client_secret" not in data.keys():
          complain("Missing client_secret in " + secrets_file)

    return data

def check_status_code(code, expectation=200):
    """
    Method that checks the returned status code against the expected status code

    :param code: code to be checked
    :type code: int
    :param expectation: code that is being expected
    :type code: int
    """

    if int(code) != int(expectation):
        complain("Received unexpected status code " + str(code) + " != " + str(expectation))

def obtain_auth_token(secrets):
    """
    Method to obtain the authorization token as per the OAuth2 authorization flow

    :param secrets dictionary containing the client_id and client_secret keys and their respective values
    :type secrets: dict
    :return: authorization token
    :rtype: string
    """
    client_id = secrets['client_id']
    client_secret = secrets['client_secret']

    auth = HTTPBasicAuth(client_id, client_secret)
    client = BackendApplicationClient(client_id=client_id)
    oauth = OAuth2Session(client=client)
    try:
      token = oauth.fetch_token(token_url=TOKEN_URL, client_id=client_id, client_secret=client_secret, auth=auth)
    except Exception as exc:
      complain('Unable to obtain authentication token due to exception: ' + str(exc))

    return token

def get_transactions(session, from_date, to_date):
    """
    This method extracts the list of transactions from the given time-frame by calling the PayPal API.

    The single query cannot span across 31 days. In case the request spawns across more than 31 days, we need to query the data month-by-month and aggregate the results.

    :param session: Session to be used for the HTTP calls
    :type session: OAuth2Session object
    :return: list of transaction IDs
    :rtype: list
    """

    i = 0
    result = {}
    result[i] = [" Date", "Time", "Name", "Status Code", "Currency", "Value", "To Email Address", "Transaction ID", "Custom Number", "Quantity", "Item Title", "Country Code"]

    query_start = datetime.strptime(from_date, "%Y-%m-%dT%H:%M:%S")
    request_end = datetime.strptime(to_date, "%Y-%m-%dT%H:%M:%S")

    if (request_end - query_start).days > (3 * 365):
        complain("The query can span across 3 years maximum")
    if (query_start - datetime(2016, 7, 1)).days < 0:
        complain("The historical data is available only from July 2016")

    query_count = int((request_end - query_start).days) / int(31)
    bar = ChargingBar('1/3 Listing trx   ', max=query_count, suffix = '%(percent).1f%% - %(eta)ds remaining')

    while (query_start < request_end):
        # The query needs to be split into multiple-ones if it spans across more than 31 days
        if (request_end - query_start).days > 31:
            query_end = query_start + timedelta(days=31)
        else:
            query_end = request_end

        page = 1
        total_pages = 1
        # The response might come in multiple pages and each needs to be queried separately
        while (page <= total_pages):
            params = (
                ("start_date", query_start.strftime("%Y-%m-%dT%H:%M:%S") + TIMEZONE_OFFSET),
                ("end_date", query_end.strftime("%Y-%m-%dT%H:%M:%S") + TIMEZONE_OFFSET),
                ("fields", "all"),
                ("page_size", "500"), # The maximum amount of transaction IDs per page is 500
                ("page", str(page))
            )

            response = session.get(TRX_URL, params=params)
            check_status_code(response.status_code)
            
            reply = json.loads(response.content)
            total_pages = int(reply['total_pages'])

            # Append the data to the resulting list
            for trx in reply['transaction_details']:
#                print('TRX DETAILS: '+ str(trx) + '\n')
                trx_data = []

                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_initiation_date'])[:10])         # Date
                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_initiation_date'])[12:19])       # Time
                trx_data.append(extract_value(trx, ['payer_info', 'payer_name', 'alternate_full_name']))              # Name
                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_status']))                       # Status Code
                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_amount', 'currency_code']))      # Currency
                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_amount', 'value']))              # Value
                trx_data.append(extract_value(trx, ['payer_info', 'email_address']))                                  # To Email Address
                trx_data.append(extract_value(trx, ['transaction_info', 'transaction_id']))                           # Transaction ID
                trx_data.append(extract_value(trx, ['transaction_info', 'custom_field']))                             # Custom Number
                count = 0.0
                title = ""
                for item in extract_value(trx, ['cart_info', 'item_details']):
                    count += float(extract_value(item, ['item_quantity']))
                    title += extract_value(item, ['item_name']) + "; "
                trx_data.append(int(count))                                                                           # Quantity
                trx_data.append(title)                                                                                # Item Title
                trx_data.append(extract_value(trx, ['shipping_info', 'address', 'country_code']))                     # Country code

                result[i] = trx_data
                i += 1

            page += 1

        # In case another query is required, the start_time should be 1 second after the end_time of the previous query parameter
        query_start = query_end + timedelta(seconds=1)
        bar.next()

    bar.finish()
    return result

def extract_value(dataset, keys):
    """
    Method used for extracting value from the dict.
    It comes handy when we need to silently ignore the fact that the dict doesn't have the required key. This saves us plenty of try/except blocks.

    :param dataset: dictionary object that contains the data to be extracted
    :type dataset: dict
    :param keys: list of keys for the data extraction from the dictionary
    :type keys: list
    :return: the data stored under location dataset['key1']['key2']...
    :rtype: object
    """
    data = dataset

    try:
        for key in keys:
            data = data[key]
    except KeyError:
        data = ""

    return data

def merge_transactions(base, new):
    """
    Applying some heuristic to merge the transactions that seem like are linked to a single event.

    :param base: list of transaction data that is used as a base for merging
    :type base: list of strings
    :param new: list of transaction data that is merged with the base transaction
    :type new: list of strings
    :return: list of transaction data as a result of the merge operation
    :rtype: list of strings
    """

    result = base

    # Check the fields one-by-one
    for i in range(max(len(base), len(new))):
        # Generic element handling
        try:
            if result[i] == "":
                # In case of an empty data cell, use the data from the 'new' transaction
                result[i] = new[i]
                continue
        except IndexError:
            if len(result) < len(new):
                # In case there's more elements in the new trx, copy them into the result
                result.append(new[i])
                continue

        # Specific element handling
        if i == 4:
            # Processing Currency
            if result[i] != BASE_CURRENCY:
                # We filter out non-BASE_CURRENCY values
                result[i] = new[i]
                # If we update the currency, we need to update the price as well
                result[i+1] = new[i+1]
        if i == 5:
            # Processing Value
            if new[i-1] != BASE_CURRENCY:
                # In case the new transaction is in foreign currency we don't mess with the value
                continue
            if (result[i] != new[i]):
                if abs(float(result[i])) == abs(float(new[i])):
                    # This means that one transaction is to charge the account, the other is the debit
                    # We are interested in the debit (i.e. <0)
                    if float(result[i]) < 0:
                        continue
                    else:
                        result[i] = new[i]
                else:
                    print("WARN: Unexpected situation occurred while merging transactions\n{}\n{}\n".format(result, new), file=sys.stderr)
                    print("WARN: Transaction has been ignored\n")

    return result

def combine_transactions(trx_data):
    """
    Method used for merging the transactions together. A single paypal payment is often translated into multiple
    transactions (e.g. conversion to foreign currency means +2 transactions). As this is a redundant information
    for us, we'd like to merge this into a single record.

    :param trx_data: transaction data written in a dict, with primary key that reflects the order in time
    :type trx_data: dict
    :return: filtered and merged transaction data, with primary key as the order in time in which the actions
             happened
    :rtype: dict
    """
    result = {}
    bar = ChargingBar('3/3 Merging trx   ', max=len(trx_data.keys()), suffix = '%(percent).1f%% - %(eta)ds remaining')
    for i in sorted(trx_data.keys()):
        # First create groups of transactions based on the time in which they occurred
        timestamp = trx_data[i][0] + 'T' + trx_data[i][1]
        if timestamp not in result.keys():
            # The first transaction we came across at this time
            result[timestamp] = trx_data[i]
        else:
            # Another transaction from this time already exist and they both need to be merged
            result[timestamp] = merge_transactions(result[timestamp], trx_data[i])

        bar.next()

    bar.finish()
    return result


def store_tsv(filename, trx_data):
    """
    Method used to write the data into the TSV (table-separated-values) file.

    :param filename: name of the file to write to
    :type filename: string
    :param trx_data: data content to be written in dict, with primary key that reflects the order for writing
    :type trx_data: dict
    """
    print("Storing the filtered and merged results: {} trx in total.".format(len(trx_data)))
    with open(filename, 'w') as tsv_file:
        writer = csv.writer(tsv_file, delimiter='\t')
        for trx in sorted(trx_data.keys()):
            writer.writerow(trx_data[trx])

def main(arguments):
    """
    This is the main loop.
    """
    session = requests.Session()
    """ Uncomment below for DEBUG logging
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.propagate = True
    """

    secrets = load_secrets()
    token = obtain_auth_token(secrets)
    session = OAuth2Session(secrets['client_id'], token=token)
    trx_data = get_transactions(session, arguments['--from-date'], arguments['--to-date'])
    trx_data = combine_transactions(trx_data)
    store_tsv(FILENAME, trx_data)

#
# Main script body
#
if __name__ == "__main__":
    arguments = docopt(__doc__, version='TSV Parser 1.0')
    validate_params(arguments)
    main(arguments)
