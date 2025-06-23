#!/usr/bin/env python3
import argparse
import requests
import time


def print_request_error_and_sleep(message, err, retry_count):
    print("[" + str(retry_count) + "] " + message, err)
    time.sleep(5)


def try_get(url):
    retries = 3
    for i in range(retries):
        try:
            if "coordinator" in url:
                r = requests.get(
                    url,
                    timeout=5,
                    headers={"x-trino-user": "admin"},
                    auth=("admin", "admin"),
                    verify=False,
                )
            else:
                r = requests.get(
                    url, timeout=5, headers={"x-trino-user": "admin"}, verify=False
                )
            r.raise_for_status()
            return r
        except requests.exceptions.HTTPError as errh:
            print_request_error_and_sleep("Http Error: ", errh, i)
        except requests.exceptions.ConnectionError as errc:
            print_request_error_and_sleep("Error Connecting: ", errc, i)
        except requests.exceptions.Timeout as errt:
            print_request_error_and_sleep("Timeout Error: ", errt, i)
        except requests.exceptions.RequestException as err:
            print_request_error_and_sleep("Error: ", err, i)

    exit(-1)


def check_monitoring(hosts):
    for host in hosts:
        # test for the jmx exporter metrics
        url = "http://" + host + ":8081/metrics"
        response = try_get(url)

        if not response.ok:
            print("Error for [" + url + "]: could not access monitoring")
            exit(-1)

        # test for the native metrics
        url = "https://" + host + ":8443/metrics"
        response = try_get(url)

        if response.ok:
            # arbitrary metric was chosen to test if metrics are present in the response
            if "io_airlift_node_name_NodeInfo_StartTime" in response.text:
                continue
            else:
                print("Error for [" + url + "]: missing metrics")
                exit(-1)
        else:
            print("Error for [" + url + "]: could not access monitoring")
            exit(-1)


if __name__ == "__main__":
    all_args = argparse.ArgumentParser(description="Test Trino metrics.")
    all_args.add_argument(
        "-c", "--coordinator", help="The coordinator service name", required=True
    )
    all_args.add_argument(
        "-w", "--worker", help="The worker service name", required=True
    )
    args = vars(all_args.parse_args())
    service_coordinator = args["coordinator"]
    service_worker = args["worker"]

    hosts = [service_coordinator, service_worker]

    check_monitoring(hosts)

    print("Test check-metrics.py succeeded!")
