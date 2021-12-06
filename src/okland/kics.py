#!/usr/bin/env python3

import os
import sys
import json
import shlex
import uuid
import docker
from .generics import Okland
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway, write_to_textfile


class Kics(Okland):
    """
    subcommands for source kics.io

    wrapper for dealing with static code analysis from kics.io.

    okland can either parse a pregenerated results file or execute a kics scan on the fly.

    Parameters
    ----------
    results: stringg
        existing file results.json. if given no scan is executed

    scan: bool
        execute a scan and work with its results

    dir: string
        directory to scan

    debug: bool
        print some debug output

    """
    __fileLocation__ = None
    __content__ = None
    __dbg__ = False
    __scan__ = False
    __scanDir__ = None
    __repoName__ = None

    def __init__(self, results="results.json", debug=False, scan=False, dir=os.getcwd()):
        if not os.path.isabs(results):
            self.__fileLocation__ = os.path.join(os.getcwd(), results)
        else:
            self.__fileLocation__ = results

        self.__repoName__ = os.path.basename(os.getcwd())
        self.__dbg__ = debug
        self.__scan__ = scan
        if not os.path.isabs(dir):
            self.__scanDir__ = os.path.join(os.getcwd(), dir)
        else:
            self.__scanDir__ = dir

    def __loadResult__(self):
        if self.__scan__:
            self.__repoName__ = os.path.basename(self.__scanDir__)
            super(Kics, self).__toConsole__(message=f"Executing kics scan for {self.__repoName__}.", style="yellow")
            self.__doScan__()
            self.__fileLocation__ = os.path.join(self.__scanDir__, "results.json")

        try:
            with open(self.__fileLocation__) as json_file:
                self.__content__ = json.load(json_file)
        except Exception as e:
            super(Kics, self).__toConsole__("Error while parsing (%s). %s" % (self.__fileLocation__, e), style="red")
            sys.exit(1)

    def __doScan__(self, dir=os.getcwd()):
        """
        execute a kics scan in a defined directory via docker instead of using a pregenerated file.
        """
        cmd = [
            'scan',
            '-p',
            '/path',
            '-o',
            '/path',
            '--minimal-ui',
            '--ignore-on-exit',
            'results'
        ]

        repository = 'checkmarx/kics'
        tag = 'latest'
        try:
            client = docker.from_env()
            client.images.pull(repository=repository, tag=tag)
            client.containers.run(image=("%s:%s" % (repository, tag)), command=cmd, remove=True, volumes=['{}:/path'.format(self.__scanDir__)], tty=True, stdout=True)
        except docker.errors.ContainerError:
            pass
        except Exception as e:
            super(Kics, self).__toConsole__("Error while running kics via docker.\ncmd would have been: (%s).\n%s" % (shlex.join(cmd), e), style="red")

    def summary(self, style="white"):
        """
        print a high level summary
        """
        self.__loadResult__()
        super(Kics, self).__toConsole__(message="Scan summary: ", style=style)
        for sev in self.__content__['severity_counters']:
            consolestyle = style
            if self.__content__['severity_counters'][sev] > 10:
                consolestyle = "red"
            elif self.__content__['severity_counters'][sev] > 5:
                consolestyle = "yellow"
            message = "  %s: %s" % (sev, self.__content__['severity_counters'][sev])

            super(Kics, self).__toConsole__(message=message, style=consolestyle)

        super(Kics, self).__toConsole__(message="---", style=consolestyle)
        super(Kics, self).__toConsole__(message=("Scanned in %s" % self.__content__['paths']), style=consolestyle)
        super(Kics, self).__toConsole__(message=("Scanned files %s" % self.__content__['files_scanned']), style=consolestyle)
        super(Kics, self).__toConsole__(message=("Queries %s" % self.__content__['queries_total']), style=consolestyle)

    def filter(self, severity="all", detail=False):
        """
        filter findings by their state (e.g. high).

        Parameters
        ----------
        severity: string
            Only show findings with this severity. (e.g --severity=MEDIUM)

        detail: bool
            Set to True to see lot more output

        """
        self.__loadResult__()
        super(Kics, self).__toConsole__(message="Issues details, filtered for severity (%s): " % severity, style="white")
        count = 0
        for rslt in self.__content__['queries']:
            if severity == "all" or rslt['severity'].lower() == severity.lower():
                count += 1

                # drop additional details
                if not detail:
                    rslt.pop('files', None)

                # shorten addtional details
                if detail:
                    pass

                rslt.pop('description_id', None)
                super(Kics, self).__toConsole__(message=rslt)
        super(Kics, self).__toConsole__(message="Shown %s of %s issues: " % (count, len(self.__content__['queries'])), style="white")

    def view(self, id=None):
        """
        see details for one issue filtered by id

        e.g. view --id="7c81d34c-8e5a-402b-9798-9f442630e678"
        """
        self.__loadResult__()
        if id is not None:
            for rslt in self.__content__['queries']:
                if rslt['query_id'] == id:
                    super(Kics, self).__toConsole__(message=rslt)

    def send(self, pushgateway="localhost:9091", jobname="Kics", simulate=False, metricprefix="okland_kics"):
        """
        send an extracted collection of metrics over to a prometheus pushgateway

        Parameters
        ----------
        pushgateway: string
            Endpoint of a prometheus pushgateway, e.g. my-pushgateway.cluster.local:9091

        simulate: bool
            just output the prometheus metrics to stdout and exit.

        jobname: string
            Jobname for metrics to be identified in pushgateway

        metricprefix: string
            Prefix for all metrics.

        """
        self.__loadResult__()
        registry = CollectorRegistry()

        if metricprefix[-1] == '_':
            metricprefix = metricprefix[:-1]

        # collect scan meta data
        meta_data = {
            'files_scanned': {'value': self.__content__['files_scanned'], 'help': 'Number of files scanned'},
            'files_parsed': {'value': self.__content__['files_parsed'], 'help': 'Number of files parsed'},
            'files_failed_to_scan': {'value': self.__content__['files_failed_to_scan'], 'help': 'Number of files that failed.'},
            'queries_total': {'value': self.__content__['queries_total'], 'help': 'Total Number of loaded queries.'},
            'queries_failed_to_execute': {'value': self.__content__['queries_failed_to_execute'], 'help': 'Number of failed queries.'},
        }

        for k, v in meta_data.items():
            Gauge(f"{metricprefix}_{k}", f"Number of {v['help']}", ['repo'], registry=registry).labels(self.__repoName__).set(v['value'])

        # collect scan summary
        ks = Gauge(f"{metricprefix}_counter", 'Number of vulns for severity.', ['repo', 'severity'], registry=registry)
        for sev in self.__content__['severity_counters']:
            ks.labels(self.__repoName__, sev.lower()).set(self.__content__['severity_counters'][sev])

        # scan detail
        kq = Gauge(f"{metricprefix}_query", 'Numbers of files matched this query.', ['name', 'severity', 'platform', 'repo'], registry=registry)
        for rslt in self.__content__['queries']:
            kq.labels(rslt['query_name'].replace(' ', '_').replace('-', '_')[:63].lower(), rslt['severity'].lower(), rslt['platform'], self.__repoName__).set(len(rslt['query_name']))

        # print content to stdout also
        if self.__dbg__ or simulate:
            tmpFile = os.path.join(os.getcwd(), "%s.prom" % (uuid.uuid4().hex))
            write_to_textfile(tmpFile, registry)
            with open(tmpFile, 'r') as f:
                print(f.read())
            os.remove(tmpFile)
        if simulate:
            super(Kics, self).__toConsole__("Simulation Mode. Exiting now.")
            sys.exit(0)
        try:
            push_to_gateway("http://{}".format(pushgateway), job=jobname, registry=registry)
        except Exception as e:
            super(Kics, self).__toConsole__("Error while sending data to configured pushgateway (http://%s). %s" % (pushgateway, e), style="red")
