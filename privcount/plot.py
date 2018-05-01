#!/usr/bin/env python
# See LICENSE for licensing information

import argparse
import json
import logging
import math
import os
import sys

from itertools import cycle
from math import sqrt
# NOTE see plotting imports below in import_plotting()

"""
python privcount/plot.py --help

compare output from multiple privcount results files.

Usage:
    python privcount/plot.py -o results1.txt test1 -o results2.txt test2 ...
"""

# When the input file doesn't have an excess noise ratio, use this value
DEFAULT_EXCESS_NOISE_RATIO = 3.0

# If we had 100% of the network, we would see 10**15 bytes every 24 hours
# Our counters aren't limited to 2**64, but the graphs might not like it
MAX_VALUE = 10**18

# The maximum length of a label in a graph
MAX_LABEL_LEN = 15

# The graph line formats
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

   # Input file arguments

    parser.add_argument('-o', '--outcome',
        help="""Append a PATH to a privcount outcome.json or tallies.json file,
                and the LABEL we should use for the graph legend for this
                set of experimental results.""",
        metavar=("PATH", "LABEL"),
        nargs=2,
        action=PlotDataAction,
        dest="data_outcome",
        default=[])

    # deprecated and hidden, use --outcome instead
    parser.add_argument('-t', '--tallies',
        help=argparse.SUPPRESS,
        metavar=("PATH", "LABEL"),
        nargs=2,
        action=PlotDataAction,
        dest="data_tallies",
        default=[])

    # deprecated and hidden, use --outcome instead
    parser.add_argument('-d', '--data',
        help=argparse.SUPPRESS,
        metavar=("PATH", "LABEL"),
        nargs=2,
        action=PlotDataAction,
        dest="experiments",
        default=[])

    # Output data arguments

    # Determining Values and Confidence Intervals

    parser.add_argument('-c', '--confidence',
        help="""Graph a confidence interval of NUM standard deviations based
                on the noise sigma for the counter. NUM can be 0.0 to disable
                graphing confidence intervals.""",
        # Use scipy.special.erfinv(FRACTION) * math.sqrt(2.0) to calculate
        # the required number of standard deviations for a FRACTION confidence
        # interval. For example:
        # >>> scipy.special.erfinv(0.95) * math.sqrt(2.0)
        # 1.959963984540054
        metavar="NUM",
        action="store",
        dest="noise_stddev",
        # Default to a 95.4% confidence interval, or 2 standard deviations
        default="2")

    parser.add_argument('-z', '--zero-bound',
        help="""Assume that values and confidence intervals have a minimum
                value of zero.""",
        action="store_true",
        dest="bound_zero")

    # Bin Labels

    parser.add_argument('-b', '--bin-labels',
        help="""Label bins with the LABELS from each counter.
                LABELS can be 'range' for bin range, 'file' for the name of
                the CountList file for the bin, 'content' for the content of
                the CountList for the bin, or a path to a file containing a
                list of newline-separated custom bin labels. Custom bin labels
                only work if each counter has the same number of bins.""",
        metavar="LABELS",
        action="store",
        dest="bin_label_source",
        default="range")

    # Output format arguments

    parser.add_argument('-f', '--format',
        help="""A comma-separated LIST of color/line format strings to cycle to
                matplotlib's plot command (see matplotlib.pyplot.plot).""",
        metavar="LIST",
        action="store",
        dest="lineformats",
        default=LINEFORMATS)

    # Output file arguments

    parser.add_argument('-p', '--prefix',
        help="A STRING filename prefix for graphs we generate.",
        metavar="STRING",
        action="store",
        dest="prefix",
        default=None)

    parser.add_argument('-w', '--skip-pdf',
        help="""Do not output a PDF file containing the results.""",
        action="store_true",
        dest="skip_pdf")

    parser.add_argument('-x', '--skip-txt', '--skip-text',
        help="""Do not output a text file containing the results.""",
        action="store_true",
        dest="skip_text")

def run_plot(args):

    # load the input files
    inputs = load_input_data(get_experiments(args))

    # extract the counter data
    counters = collect_counters(inputs, args.bin_label_source)

    # calculate some additional values
    calculate_bound_values(counters, args.bound_zero)
    calculate_error_values(counters, args.bound_zero, args.noise_stddev)
    calculate_bin_reliability(counters)

    # create the output file prefix
    output_prefix = get_output_prefix(args)

    # output the text file
    if not args.skip_text:
        text_output_name = "{}privcount.results.txt".format(output_prefix)
        output_text_file(text_output_name, counters, args.bound_zero)

    # output the PDF file
    if not args.skip_pdf:
        pdf_output_name = "{}privcount.results.pdf".format(output_prefix)
        plot_info = get_plot_info(counters, get_lineformats(args.lineformats))
        plot_pdf(pdf_output_name, plot_info)

def load_input_data(experiments):
    '''
    Load each input file in experiments, and return an array of inputs.
    '''
    # load all the input file data
    inputs = []
    for (path, experiment_label) in experiments:
        logging.info("Loading results for '{}' from input file '{}'"
                     .format(experiment_label, path))
        (histograms, privacy, sigmas, bin_labels) = load_input_file(path)
        input_file = {
            'path' : path,
            'experiment_label' : experiment_label,
            'histograms' : histograms,
            'privacy' : privacy,
            'sigmas' : sigmas,
            'bin_labels' : bin_labels,
        }
        inputs.append(input_file)

    return inputs

def load_input_file(path):
    '''
    Load the input file at path, and return a tuple containing
    (histograms, privacy, sigmas, labels).
    '''
    with open(path, 'r') as fin:
        data = json.load(fin)

        if 'Tally' in data: # this is an outcome file
            histograms = data['Tally']
        else: # this is a tallies file
            histograms = data

        if 'Context' in data: # this is an outcome file that has privacy values
            privacy = data['Context']['TallyServer']['Config']['noise']['privacy']
        else: # this is a tallies file that does not have privacy values
            privacy = {}

        if 'Context' in data: # this is an outcome file that has sigma values
            sigmas = data['Context']['TallyServer']['Config']['noise']['counters']
        else: # this is a tallies file that *might* have sigma values
            sigmas = histograms

        if 'Context' in data: # this is an outcome file that *might* have labels
            labels = data['Context']['TallyServer']['Config']
        else: # this is a tallies file that has no labels
            labels = {}

    return (histograms, privacy, sigmas, labels)

def get_experiments(args):
    '''
    Return the list of experiments from args.
    Throws an exception if the list of experiments is invalid.
    '''
    experiments = args.experiments + args.data_tallies + args.data_outcome
    if len(experiments) == 0:
        raise ValueError("You must provide at least one input file using --outcome. For more details, use --help.")
    return experiments

def collect_counters(inputs, bin_label_source):
    '''
    Find all the counters in inputs, and return them in an array.
    Collect bin labels, and assign a preferred label based on
    bin_label_source.
    '''
    # collect all the counters from all input files
    counters = []
    for input_file in inputs:

        experiment_label = input_file['experiment_label']
        histograms = input_file['histograms']
        privacy = input_file['privacy']
        sigmas = input_file['sigmas']
        bin_labels = input_file['bin_labels']

        excess_noise_ratio = get_excess_noise_ratio(privacy)

        # go through all the counters
        for counter_name in sorted(histograms.keys()):

            sigma = get_sigma(counter_name, sigmas)

            counter = {
                'experiment_label' : experiment_label,
                'excess_noise_ratio' : excess_noise_ratio,
                'name' : counter_name,
                'sigma' : sigma,
                'bins' : [],
            }

            # go through all the bins
            for (left, right, value) in histograms[counter_name]['bins']:
                bin = {
                    'left' : left,
                    'right' : right,
                    'value' : value,
                }
                counter['bins'].append(bin)

            collect_bin_labels(counter, bin_labels, bin_label_source)

            counters.append(counter)

    return counters

def get_excess_noise_ratio(privacy):
    '''
    Return the excess_noise_ratio in privacy as a float, if it exists and is
    valid. Otherwise, return DEFAULT_EXCESS_NOISE_RATIO, if it is valid.
    Otherwise, if neither value is valid, return None.
    '''
    excess_noise_ratio = privacy.get('excess_noise_ratio',
                                     DEFAULT_EXCESS_NOISE_RATIO)

     # a zero ratio means "no noise", so we don't show any error bars
    if float(excess_noise_ratio) > 0.0:
        return excess_noise_ratio
    else:
        return None

def get_sigma(counter_name, sigmas):
    '''
    Return the sigma for counter_name as a float, if it exists and is valid.
    Otherwise, return None.
    '''
    sigma = sigmas[counter_name].get('sigma', 0.0)
    # a zero sigma means "no noise", so we don't show any error bars
    if float(sigma) > 0.0:
        return sigma
    else:
        return None

def collect_bin_labels(counter, bin_labels, bin_label_source):
    '''
    Collect all the available bin labels out of bin_labels for each counter,
    and add them to the bin dicts. Also add the default label based on
    bin_label_source.
    '''
    name = counter['name']
    bins = counter['bins']

    # get all the different types of bin labels
    bin_file_labels = get_bin_labels(name,
                                     len(bins),
                                     bin_labels,
                                     'file')

    bin_content_labels = get_bin_labels(name,
                                     len(bins),
                                     bin_labels,
                                     'content')
    bin_custom_labels = []
    if bin_label_source not in ['range', 'file', 'content']:
        bin_custom_labels = get_bin_labels(name,
                                           len(bins),
                                           bin_labels,
                                           bin_label_source)

    bin_preferred_labels = get_bin_labels(name,
                                          len(bins),
                                          bin_labels,
                                          bin_label_source)

    # go through all the bins and label them
    label_index = 0
    for bin in bins:

        left = bin['left']
        right = bin['right']

        bin['range_label'] = "[{:.1f},{:.1f})".format(left, right)

        if left == float('-inf'):
            left = '{}'.format(r'$-\infty$')
        elif not name.endswith('Ratio'):
            left = int(left)

        if right == float('inf'):
            right = '{}'.format(r'$\infty$')
        elif not name.endswith('Ratio'):
            right = int(right)

        bin['graph_range_label'] = "[{},{})".format(left, right)

        if len(bin_file_labels) > 0:
            bin['file_label'] = bin_file_labels[label_index]

        if len(bin_content_labels) > 0:
            bin['content_label'] = bin_content_labels[label_index]

        if len(bin_custom_labels) > 0:
            bin['custom_label'] = bin_custom_labels[label_index]

        if len(bin_preferred_labels) > 0:
            bin['label'] = bin_preferred_labels[label_index]
        else:
            bin['label'] = bin['range_label']

        if len(bin_preferred_labels) > 0:
            bin['graph_label'] = bin_preferred_labels[label_index]
            if len(bin['graph_label']) > MAX_LABEL_LEN:
                bin['graph_label'] = bin['graph_label'][0:(MAX_LABEL_LEN-3)] + '...'
        else:
            bin['graph_label'] = bin['graph_range_label']

        label_index += 1

def get_bin_labels(counter_name, bin_count, bin_labels, bin_label_source):
    '''
    Return an array of bin labels for counter_name from bin_labels, selected
    using bin_label_source. See args.bin_label_source for details.

    Returns an empty array to indicate that the default range labels should
    be used.

    If the number of labels is one less than bin_count, adds an '(unmatched)'
    label for the final bin.

    Asserts if the final number of labels is not equal to bin_count.
    '''

    labels = []
    if bin_label_source == 'range':
        # we don't want to override the standard range labels
        pass
    elif bin_label_source in ['file', 'content']:
        c = (bin_label_source == 'content')

        # add the match list bin labels for count lists
        # we don't have custom labels for any other counters
        if counter_name.endswith('CountList'):
            # These plot lookups should be kept synchronised with the
            # corresponding TallyServer config options
            if counter_name.startswith("ExitDomain"):
                labels = bin_labels.get('domain_lists' if c else 'domain_files', [])
            if "CountryMatch" in counter_name:
                labels = bin_labels.get('country_lists' if c else 'country_files', [])
            if "ASMatch" in counter_name:
                # the AS data structure is slightly more complex than the others
                labels = bin_labels.get('as_raw_lists' if c else 'as_files', [])
            if (counter_name.startswith("HSDir") and
                "Store" in counter_name and
                counter_name.endswith("ReasonCountList")):
                labels = bin_labels.get('hsdir_store_lists' if c else 'hsdir_store_files', [])
            if (counter_name.startswith("HSDir") and
                "Fetch" in counter_name and
                counter_name.endswith("ReasonCountList")):
                labels = bin_labels.get('hsdir_fetch_lists' if c else 'hsdir_fetch_files', [])
            if counter_name.endswith("FailureCircuitReasonCountList"):
                labels = bin_labels.get('circuit_failure_lists' if c else 'circuit_failure_files', [])
            if (counter_name.startswith("HSDir") and
                ("Store" in counter_name or "Fetch" in counter_name) and
                counter_name.endswith("OnionAddressCountList")):
                labels = bin_labels.get('onion_address_lists' if c else 'onion_address_files', [])

        # strip redundant information
        stripped_labels = []
        for label_str in labels:
            # strip 1-element content summaries down to the actual content
            if label_str.endswith(' (1)'):
                label_str, _, _ = label_str.rpartition(' ')
                label_str = label_str.strip("'")

            # strip file paths down to the filename
            if label_str.startswith('/'):
                _, _, label_str = label_str.rpartition('/')
                label_str, _, _ = label_str.rpartition('.')
            stripped_labels.append(label_str)

        labels = stripped_labels
    else:
        with open(bin_label_source, 'r') as fin:
            labels = [line.strip() for line in fin.readlines()]

    # a zero-length array means 'use the range'
    if len(labels) > 0:
        # add the unmatched bin label
        if len(labels) < bin_count:
            labels.append('(unmatched)')
        # check we have the right number of labels
        assert len(labels) == bin_count

    return labels

def calculate_bound_values(counters, bound_zero):
    '''
    Calculated a bounded value for every bin in counter, and add it to that
    counter's dict.

    If bound_zero is True, bound to zero as well as MAX_VALUE.
    '''
    # go through all the counters
    for counter in counters:

        # go through all the bins
        for bin in counter['bins']:
            value = bin['value']
            # now bound the value
            bound_value = min(value, MAX_VALUE)
            if bound_zero:
                bound_value = max(bound_value, 0)
            bin['bound_value'] = bound_value

def calculate_error_values(counters, bound_zero, noise_stddev):
    '''
    Calculate error differences for every counter using the sigmas in
    and excess_noise_ratios in counters, and noise_stddev.

    Calculate error values, error percentages, and bounded error values for
    every bin in every counter. Add these values to their respective dicts.

    If bound_zero is True, bound to zero as well as MAX_VALUE.
    '''
    # go through all the counters
    for counter in counters:

        # calculate the noise for the counter
        excess_noise_ratio = counter['excess_noise_ratio']
        sigma = counter['sigma']
        if (excess_noise_ratio is not None and sigma is not None and
            float(noise_stddev) > 0.0):
            # use the supplied confidence interval for the noise
            counter['error_difference'] = int(round(sigma_to_ci_amount(
                                                        noise_stddev,
                                                        excess_noise_ratio,
                                                        sigma)))
            # describe the noise on the experiment label
            counter['experiment_label_sigma'] = ("{} ({} sigma = {:.2f}% CI)"
                                                 .format(counter['experiment_label'],
                                                         noise_stddev,
                                                         100.0*stddev_to_ci_fraction(noise_stddev)))

            # go through all the bins
            for bin in counter['bins']:

                # calculate error percentage
                # avoid division by zero
                if abs(bin['value']) != 0:
                    bin['error_proportion'] = float(counter['error_difference']) / abs(bin['value'])
                else:
                    bin['error_proportion'] = float('inf')

                # calculate the error bounds
                bin['error_value_low'] = bin['value'] - counter['error_difference']
                bin['error_value_high'] = bin['value'] + counter['error_difference']

                # always bound the value above
                # we don't expect any noise or values larger than MAX_VALUE
                bound_error_value_low = min(bin['error_value_low'], MAX_VALUE)
                bound_error_value_high = min(bin['error_value_high'], MAX_VALUE)

                # conditionally bound below
                if bound_zero:
                    bound_error_value_low = max(bound_error_value_low, 0)
                    bound_error_value_high = max(bound_error_value_high, 0)

                bin['bound_error_value_low'] = bound_error_value_low
                bin['bound_error_value_high'] = bound_error_value_high

                # reconstruct the bound differences from the bound values
                bin['bound_error_difference_low'] = bin['bound_value'] - bin['bound_error_value_low']
                bin['bound_error_difference_high'] = bin['bound_error_value_high'] - bin['bound_value']

def sigma_to_ci_amount(noise_stddev, excess_noise_ratio, sigma_value):
    '''
    Return the noise_stddev standard deviation confidence interval amount
    for sigma_value, based on excess_noise_ratio.
    '''
    return float(noise_stddev) * sqrt(excess_noise_ratio) * float(sigma_value)

def stddev_to_ci_fraction(noise_stddev):
    '''
    Return the noise_stddev standard deviation confidence interval fraction.
    '''
    return math.erf(float(noise_stddev) / sqrt(2.0))

def calculate_bin_reliability(counters):
    '''
    Calculate various aspects of the reliability of each bin. Add these values
    to the bin dicts.
    '''
    # go through all the counters
    for counter in counters:

        # go through all the bins
        for bin in counter['bins']:

            # could the result be zero (or negative), or is it most likely positive?
            bin['is_possibly_zero'] = (bin.get('error_value_low', bin['value']) <= 0)

            # is the error proprotion too large?
            bin['is_noisy'] = (bin.get('error_proportion', 0.0) >= 1.0)

            # work out which values were bounded
            bin['is_value_bounded'] = (bin['value'] != bin['bound_value'])
            bin['is_error_low_bounded'] = (bin.get('bound_error_difference_low', 0) != bin.get('error_difference', 0))
            bin['is_error_high_bounded'] = (bin.get('bound_error_difference_high', 0) != bin.get('error_difference', 0))

            # alternate representation for text output
            bin['status'] = []

            # is the value mostly noise?
            if bin['is_noisy']:
                bin['status'].append('obscured')
            else:
                bin['status'].append('visible')

            # does the confidence interval include zero?
            if bin['is_possibly_zero']:
                bin['status'].append('zero')
            else:
                bin['status'].append('positive')

            # work out which values were bounded
            bin['bounded'] = []

            if bin['is_value_bounded']:
                bin['bounded'].append('value')
            if bin['is_error_low_bounded']:
                bin['bounded'].append('error low')
            if bin['is_error_high_bounded']:
                bin['bounded'].append('error high')

def get_output_prefix(args):
    '''
    Return the prefix from args.
    '''
    return args.prefix + '.' if args.prefix is not None else ''

def output_text_file(text_output_name, counters, bound_zero):
    '''
    Output a text file at text_output_name with detailed information about
    each bin in counters. Include bounding information if bound_zero is true,
    or MAX_VALUE was reached.
    '''
    logging.info("Writing results to text file '{}'".format(text_output_name))

    with open(text_output_name, 'w') as text_output:

        # go through all the counters
        previous_experiment_label = None
        for counter in counters:

            # print the label for each new experiment
            experiment_label = counter.get('experiment_label_sigma', counter['experiment_label'])
            if previous_experiment_label != experiment_label:
                text_output.write("Experiment Label: {}\n".format(experiment_label))
                previous_experiment_label = experiment_label

            # adding formatting information to counter is an acceptable abstraction violation
            if 'error_difference' in counter:
                # justify up to the error length, plus a few digits and a negative
                counter['value_justify'] = len(str(counter['error_difference'])) + 3
            else:
                # justify long
                counter['value_justify'] = 14

            # go through all the bins
            # log the raw error bounds, and note when the result is useful
            for bin in counter['bins']:

                if 'error_proportion' in bin:
                    # assume all the other fields are present in counter and bin
                    error_str = (" +- {:.0f} ({:7.1f}%)"
                                 .format(counter['error_difference'],
                                         bin['error_proportion']*100.0))
                    bound_str = " bound: {} [{}, {}] ({})".format(
                                      str(bin['bound_value']).rjust(counter['value_justify']),
                                      str(bin['bound_error_value_low']).rjust(counter['value_justify']),
                                      str(bin['bound_error_value_high']).rjust(counter['value_justify']),
                                      ', '.join(bin['bounded']) if len(bin['bounded']) > 0 else 'no change')
                else:
                    error_str = ''
                    bound_str = " bound: {} ({})".format(
                                      str(bin['bound_value']).rjust(counter['value_justify']),
                                      ', '.join(bin['bounded']) if len(bin['bounded']) > 0 else 'no change')

                # only print non-default labels, because we already print the range
                if bin['label'] != bin['range_label']:
                    label_str = " '{}'".format(bin['label'])
                else:
                    label_str = ''

                bin_txt = ("{} [{:8.1f},{:8.1f}){} = {}{} ({}){}\n"
                           .format(counter['name'],
                                   bin['left'],
                                   bin['right'],
                                   label_str,
                                   str(bin['value']).rjust(counter['value_justify']),
                                   error_str,
                                   ", ".join([s.rjust(8) for s in bin['status']]),
                                   bound_str if bound_zero or len(bin['bounded']) > 0 else ''))
                text_output.write(bin_txt)

def get_plot_info(counters, line_formats):
    '''
    Returns the data needed to graph counters, using line_formats.
    '''
    plot_info = {}

    # go through all the counters
    previous_experiment_label = None
    for counter in counters:

        name = counter['name']

        # change the colour for each new experiment
        experiment_label = counter['experiment_label']
        if previous_experiment_label != experiment_label:
            dataset_color = line_formats.next()
            previous_experiment_label = experiment_label

        # setup the plot_info for this counter
        plot_info.setdefault(name, {'datasets':[], 'errors':[], 'dataset_colors':[], 'dataset_labels':[], 'bin_labels':[]})
        plot_info[name]['dataset_colors'].append(dataset_color)

        # work out the graph label
        if 'experiment_label_sigma' in counter:
            # label the graph with the sttdev and CI, and a pretty sigma
            dataset_label = counter['experiment_label_sigma'].replace('sigma', r'$\sigma$')
        else:
            dataset_label = counter['experiment_label']

        plot_info[name]['dataset_labels'].append(dataset_label)

        # initialise the error data structure
        if ('error_difference' in counter):
            # axis.bar(yerr=) expects a 2xN array-like object
            plot_info[name]['errors'].append([[],[]])
        else:
            plot_info[name]['errors'].append(None)

        dataset = []

        # go through all the bins
        for bin in counter['bins']:
            dataset.append(bin['bound_value'])

            # add the error bounds
            if ('bound_error_difference_low' in bin and
                'bound_error_difference_high' in bin):
                # The +/- errors go in separate arrays
                plot_info[name]['errors'][-1][0].append(bin['bound_error_difference_low'])
                plot_info[name]['errors'][-1][1].append(bin['bound_error_difference_high'])

            plot_info[name]['bin_labels'].append(bin['graph_label'])

        plot_info[name]['datasets'].append(dataset)

    return plot_info

def get_lineformats(lineformats):
    '''
    Return a cycle of lineformats from lineformats.
    '''
    lflist = lineformats.strip().split(",")
    return cycle(lflist)

def plot_pdf(pdf_output_name, plot_info):
    '''
    Plot a PDF file containing plot_info, to a PDF file at pdf_output_name.
    '''
    import_plotting()

    page = PdfPages(pdf_output_name)
    logging.info("Writing results to PDF file '{}'"
                 .format(pdf_output_name))

    for name in sorted(plot_info.keys()):
        dat = plot_info[name]
        plot_page(page, dat, name)
    page.close()

def import_plotting():
    '''
    Import required plot libraries, and configure them.
    '''
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

def plot_page(page, dat, name):
    '''
    Plot a page named name into page, using the chart data in dat.
    '''
    plot_bar_chart(page, dat['datasets'], dat['dataset_labels'],
                   dat['dataset_colors'], dat['bin_labels'], dat['errors'],
                   title=name)

def plot_bar_chart(page, datasets, dataset_labels, dataset_colors,
                   x_group_labels, err,
                   title=None, xlabel='Bins', ylabel='Counts'):
    '''
    Plot a bar chart into page, using the supplied data.
    '''
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
