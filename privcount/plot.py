#!/usr/bin/env python
# See LICENSE for licensing information

import argparse
import json
import logging
import os
import sys

from itertools import cycle
from math import sqrt
# NOTE see plotting imports below in import_plotting()

"""
python plot.py --help

compare output from multiple privcount results files. run like:
python privcount/plot.py -d results1.txt test1 -d results2.txt test2 ...
"""

LINEFORMATS="k,r,b,g,c,m,y"

class PlotDataAction(argparse.Action):
    '''
    a custom action for passing in experimental data directories when plotting
    '''
    def __call__(self, parser, namespace, values, option_string=None):
        # extract the path to our data, and the label for the legend
        datapath = os.path.abspath(os.path.expanduser(values[0]))
        label = values[1]
        # check the path exists
        if not os.path.exists(datapath): raise argparse.ArgumentError(self, "The supplied path to the plot data does not exist: '{0}'".format(datapath))
        # remove the default
        if "_didremovedefault" not in namespace:
            setattr(namespace, self.dest, [])
            setattr(namespace, "_didremovedefault", True)
        # append out new experiment path
        dest = getattr(namespace, self.dest)
        dest.append((datapath, label))

def main():
    parser = argparse.ArgumentParser(
        description='Utility to help plot results from PrivCount',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    add_plot_args(parser)
    args = parser.parse_args()
    run_plot(args)

def add_plot_args(parser):

    parser.add_argument('-o', '--outcome',
        help="""Append a PATH to a privcount outcome.json file,
                and the LABEL we should use for the graph legend for this
                set of experimental results""",
        metavar=("PATH", "LABEL"),
        nargs=2,
        required=False,
        action=PlotDataAction, dest="data_outcome", default=[])

    parser.add_argument('-t', '--tallies',
        help="""Append a PATH to a privcount tallies.json file,
                and the LABEL we should use for the graph legend for this
                set of experimental results. Using '-o', '--outcome' is the
                prefered way to plot results in order to include error bars.""",
        metavar=("PATH", "LABEL"),
        nargs=2,
        required=False,
        action=PlotDataAction, dest="data_tallies", default=[])

    # deprecated and hidden, use --outcome instead
    parser.add_argument('-d', '--data',
        help=argparse.SUPPRESS,
        metavar=("PATH", "LABEL"),
        nargs=2,
        required=False,
        action=PlotDataAction, dest="experiments", default=[])

    parser.add_argument('-p', '--prefix',
        help="a STRING filename prefix for graphs we generate",
        metavar="STRING",
        action="store", dest="prefix",
        default=None)

    parser.add_argument('-f', '--format',
        help="""A comma-separated LIST of color/line format strings to cycle to
                matplotlib's plot command (see matplotlib.pyplot.plot)""",
        metavar="LIST",
        action="store", dest="lineformats",
        default=LINEFORMATS)

    parser.add_argument('-w', '--skip-pdf',
        help="""Do not output a PDF file containing the results""",
        action="store_true", dest="skip_pdf")

    parser.add_argument('-x', '--skip-txt', '--skip-text',
        help="""Do not output a text file containing the results""",
        action="store_true", dest="skip_text")

MAX_LABEL_LEN = 15

def import_plotting():
    global matplotlib
    import matplotlib; matplotlib.use('Agg') # for systems without X11
    global PdfPages
    from matplotlib.backends.backend_pdf import PdfPages
    global pylab
    import pylab

    pylab.rcParams.update({
        'backend': 'PDF',
        'font.size': 16,
        'figure.figsize': (6,4.5),
        'figure.dpi': 100.0,
        'figure.subplot.left': 0.15,
        'figure.subplot.right': 0.95,
        'figure.subplot.bottom': 0.15,
        'figure.subplot.top': 0.95,
        'grid.color': '0.1',
        'axes.grid' : True,
        'axes.titlesize' : 'small',
        'axes.labelsize' : 'small',
        'axes.formatter.limits': (-4,4),
        'xtick.labelsize' : 'small',
        'ytick.labelsize' : 'small',
        'lines.linewidth' : 2.0,
        'lines.markeredgewidth' : 0.5,
        'lines.markersize' : 10,
        'legend.fontsize' : 'x-small',
        'legend.fancybox' : False,
        'legend.shadow' : False,
        'legend.borderaxespad' : 0.5,
        'legend.numpoints' : 1,
        'legend.handletextpad' : 0.5,
        'legend.handlelength' : 1.6,
        'legend.labelspacing' : .75,
        'legend.markerscale' : 1.0,
        # turn on the following to embedd fonts; requires latex
        #'ps.useafm' : True,
        #'pdf.use14corefonts' : True,
        #'text.usetex' : True,
    })

    try: pylab.rcParams.update({'figure.max_num_figures':50})
    except: pylab.rcParams.update({'figure.max_open_warning':50})
    try: pylab.rcParams.update({'legend.ncol':1.0})
    except: pass

def run_plot(args):
    import_plotting()

    args.experiments = args.experiments + args.data_tallies + args.data_outcome
    if len(args.experiments) == 0:
        print("You must provide at least one input file using --outcome or --tallies")
        print("For more details, use --help")
        sys.exit(1)

    lflist = args.lineformats.strip().split(",")
    lfcycle = cycle(lflist)

    fprefix = args.prefix + '.' if args.prefix is not None else ''
    fout_txt_name = None
    fout_txt = None
    if not args.skip_text:
        fout_txt_name = "{}privcount.results.txt".format(fprefix)
        fout_txt = open(fout_txt_name, 'w')

    plot_info = {}
    for (path, label) in args.experiments:
        dataset_color = lfcycle.next()
        dataset_label = label
        fin = open(path, 'r')
        data = json.load(fin)
        if 'Tally' in data: # this is an outcome file
            histograms = data['Tally']
        else: # this is a tallies file
            histograms = data
        if 'Context' in data: # this is an outcome file that has sigma values
            sigmas = data['Context']['TallyServer']['Config']['noise']['counters']
        else: # this is a tallies file that *might* have sigma values
            sigmas = histograms
        if 'Context' in data: # this is an outcome file that *might* have labels
            labels = data['Context']['TallyServer']['Config']
        else: # this is a tallies file that has no labels
            labels = {}
        fin.close()

        if fout_txt is not None:
            logging.info("Writing results for '{}' to text file '{}'"
                         .format(label, fout_txt_name))
            fout_txt.write("Label: {}\n".format(label))
        for name in sorted(histograms.keys()):
            plot_info.setdefault(name, {'datasets':[], 'errors':[], 'dataset_colors':[], 'dataset_labels':[], 'bin_labels':[]})
            plot_info[name]['dataset_colors'].append(dataset_color)
            plot_info[name]['dataset_labels'].append(dataset_label)

            if 'sigma' in sigmas[name]:
                sigma = float(sigmas[name]['sigma'])
                # use the 95% confidence interval for the noise
                error = int(round(2 * sqrt(3) * sigma))
                # we don't expect any noise larger than 10**15
                error = min(error, 1000000000000000)
            else:
                error = None
            plot_info[name]['errors'].append(error)

            dataset = []
            bin_labels = []
            bin_labels_txt = []

            # CountLists
            # These plot lookups should be kept synchronised with the
            # corresponding TallyServer config options

            # add the match list bin labels for count lists
            # match histograms etc. use the first bin to match, and we don't
            # modify their labels
            if name.endswith('CountList'):
                if name.startswith("ExitDomain"):
                    bin_labels_txt = labels.get('domain_lists', [])
                if "CountryMatch" in name:
                    bin_labels_txt = labels.get('country_lists', [])
                if "ASMatch" in name:
                    bin_labels_txt = labels.get('as_lists', [])
                if (name.startswith("HSDir") and
                    "Store" in name and
                    name.endswith("ReasonCountList")):
                    bin_labels_txt = labels.get('hsdir_store_lists', [])
                if (name.startswith("HSDir") and
                    "Fetch" in name and
                    name.endswith("ReasonCountList")):
                    bin_labels_txt = labels.get('hsdir_fetch_lists', [])
                if name.endswith("FailureCircuitReasonCountList"):
                    bin_labels_txt = labels.get('circuit_failure_lists', [])
                if (name.startswith("HSDir") and
                    ("Store" in name or "Fetch" in name) and
                    name.endswith("OnionAddressCountList")):
                    bin_labels_txt = labels.get('onion_address_lists', [])
            # add the unmatched bin label
            if len(bin_labels_txt) > 0:
                if len(bin_labels_txt) < len(histograms[name]['bins']):
                    bin_labels_txt.append('(unmatched)')
                assert len(bin_labels_txt) == len(histograms[name]['bins'])
            label_index = 0
            for (left, right, val) in histograms[name]['bins']:
                # log the raw error bounds, and note when the result is useful
                status = []
                if fout_txt is not None:
                  if error is not None:
                      if abs(val) != 0:
                          error_perc = error / abs(float(val)) * 100.0
                      else:
                          error_perc = 0.0
                      # is the result too noisy, or is it visible?
                      if error_perc >= 100.0:
                          status.append('obscured')
                      else:
                          status.append('visible')
                  # could the result be zero, or is it positive?
                  if val - (error if error is not None else 0) <= 0:
                      status.append('zero')
                  else:
                      status.append('positive')
                  if error is not None:
                      error_str = (" +- {:.0f} ({:7.1f}%)"
                                   .format(error, error_perc))
                  else:
                      error_str = ''
                  if len(bin_labels_txt) > label_index:
                      label_str = bin_labels_txt[label_index]
                      # remove redundant string components for 1-element lists
                      if label_str.endswith(' (1)'):
                          label_str, _, _ = label_str.rpartition(' ')
                          label_str = label_str.strip("'")
                      label_str = " {}".format(label_str)
                  else:
                      label_str = ''
                  if  error is not None:
                      # justify up to the error length, plus one digit and a negative
                      val_just = len(str(error)) + 2
                  else:
                      # justify long
                      val_just = 14
                  val_str = str(val).rjust(val_just)
                  bin_txt = ("{} [{:5.1f},{:5.1f}){} = {}{} ({})\n"
                             .format(name, left, right, label_str,
                                     val_str, error_str,
                                     ", ".join(status)))
                  fout_txt.write(bin_txt)
                if right == float('inf'):
                    right = '{}'.format(r'$\infty$')
                elif 'Ratio' not in name:
                    right = int(right)
                if left == float('-inf'):
                    left = '{}'.format(r'$-\infty$')
                elif 'Ratio' not in name:
                    left = int(left)
                bin_labels.append("[{},{})".format(left, right))
                dataset.append(val)
                label_index += 1
            if len(bin_labels_txt) > 0:
                assert len(bin_labels_txt) == len(bin_labels)
                bin_labels = [bin_label.strip("'")[0:(MAX_LABEL_LEN-3)] + '...' if len(bin_label) > MAX_LABEL_LEN else bin_label for bin_label in bin_labels_txt]
            plot_info[name]['datasets'].append(dataset)

            if len(plot_info[name]['bin_labels']) == 0:
                plot_info[name]['bin_labels'] = bin_labels
    if fout_txt is not None:
        fout_txt.close()

    if args.skip_pdf:
        return

    fout_pdf_name = "{}privcount.results.pdf".format(fprefix)
    page = PdfPages(fout_pdf_name)
    logging.info("Writing results to PDF file '{}'"
                 .format(label, fout_pdf_name))

    for name in sorted(plot_info.keys()):
        dat = plot_info[name]
        plot_bar_chart(page, dat['datasets'], dat['dataset_labels'], dat['dataset_colors'], dat['bin_labels'], err=dat['errors'], title=name)
    page.close()

def plot_bar_chart(page, datasets, dataset_labels, dataset_colors, x_group_labels, err, title=None, xlabel='Bins', ylabel='Counts'):
    assert len(datasets) == len(err)
    assert len(datasets) == len(dataset_colors)
    assert len(datasets) == len(dataset_labels)
    for dataset in datasets:
        assert len(dataset) == len(datasets[0])
        assert len(dataset) == len(x_group_labels)

    num_x_groups = len(datasets[0])
    x_group_locations = pylab.arange(num_x_groups)
    width = 1.0 / float(len(datasets)+1)

    figure = pylab.figure()
    axis = figure.add_subplot(111)
    bars = []

    for i in xrange(len(datasets)):
        bar = axis.bar(x_group_locations + (width*i), datasets[i], width, yerr=err[i], color=dataset_colors[i], error_kw=dict(ecolor='pink', lw=3, capsize=6, capthick=3))
        bars.append(bar)

    if title is not None:
        axis.set_title(title)
    if ylabel is not None:
        axis.set_ylabel(ylabel)
    if xlabel is not None:
        axis.set_xlabel(xlabel)

    axis.set_xticks(x_group_locations + width*len(datasets)/2)
    x_tick_names = axis.set_xticklabels(x_group_labels)
    rot = 0 if num_x_groups == 1 else 15
    pylab.setp(x_tick_names, rotation=rot, fontsize=10)
    axis.set_xlim(-width, num_x_groups)
    y_tick_names = axis.get_yticklabels()
    pylab.setp(y_tick_names, rotation=0, fontsize=10)

    axis.legend([bar[0] for bar in bars], dataset_labels)
    page.savefig()
    pylab.close()

if __name__ == '__main__': sys.exit(main())
