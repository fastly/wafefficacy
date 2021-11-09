import json
import sys, getopt
import argparse

def waf_efficacy_scores(filename: str, attack_types: list):

    with open(filename, 'r') as f:
        input_data = json.load(f)
    
    true_positives = 0
    false_negatives = 0
    true_negatives = 0
    false_positives = 0

    for attack_type in attack_types:
        tp, fn = true_positives_false_negatives(attack_type, input_data)
        tn, fp = true_negatives_false_positives(attack_type, input_data)
        true_positives += tp
        false_negatives += fn
        true_negatives += tn
        false_positives += fp
        print("-------------" + attack_type.upper() + "-------------")
        print("True Positives", tp)
        print("False Negatives", fn)
        print("True Negatives", tn)
        print("False Positives", fp)
        sensitivity = tp / (tp + fn)
        specificity = tn / (tn + fp)
        balanced_accuracy = (sensitivity + specificity) / 2
        print("Efficacy", "{0:.1f}%".format(balanced_accuracy * 100))
    
    print("------------- WAF Efficacy -------------" )
    sensitivity = true_positives / (true_positives + false_negatives)
    specificity = true_negatives / (true_negatives + false_positives)
    balanced_accuracy = (sensitivity + specificity) / 2
    print("{0:.1f}%".format(balanced_accuracy * 100))


def true_positives_false_negatives(attack: str, data: dict) -> (int, int):
    true_positives = 0
    false_negatives = 0
    for result in data:
        if result['templateID'] == attack+"-true-positive":
            if "406" in result['response']:
                true_positives += 1
            else:
                false_negatives += 1

    return true_positives, false_negatives

def true_negatives_false_positives(attack: str, data: dict) -> (int, int):
    true_negatives = 0
    false_positives = 0
    for result in data:
        if result['templateID'] == attack+"-false-positive":
            if "406" in result['response']:
                false_positives += 1
            else:
                true_negatives += 1

    return true_negatives, false_positives

def main():
    parser = argparse.ArgumentParser(prog='score')
    parser.add_argument('-f', '--filename', dest='filename', required=True, help='filename of json formatted waf efficacy results', type=str)
    parser.add_argument('-a', '--attacks', dest='attacks', required=True, help='list of one or more attack types', nargs='+', type=str)
    args = parser.parse_args()
    print(args.filename, args.attacks)
    waf_efficacy_scores(args.filename, args.attacks) 

if __name__ == '__main__':
    sys.exit(main())
