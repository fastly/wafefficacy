import json
import sys
import argparse
from typing import List, Tuple

class WAFEfficacy:
    """
    Calculates WAF Efficacy Score
    """
    def __init__(self, filename: str, waf_response: str, attack_types: List[str], precision: int) -> None:
        with open(filename, 'r') as f:
            self.results = [json.loads(line) for line in f]
        self.attack_types = attack_types if attack_types else ['cmdexe', 'sqli', 'traversal', 'xss']
        self.waf_response = waf_response if waf_response else "406 Not Acceptable"
        self.precision = precision if precision else 1
    
    def __true_positives_false_negatives(self, attack_type: str) -> Tuple[int, int]:
        true_positives = 0
        false_negatives = 0
        for result in self.results:
            if result['template-id'] == attack_type+"-true-positive":
                if self.waf_response in result['response']:
                    true_positives += 1
                else:
                    false_negatives += 1
        return true_positives, false_negatives
    
    def __true_negatives_false_positives(self, attack_type: str) -> Tuple[int, int]:
        true_negatives = 0
        false_positives = 0
        for result in self.results:
            if result['template-id'] == attack_type+"-false-positive":
                if self.waf_response in result['response']:
                    false_positives += 1
                else:
                    true_negatives += 1

        return true_negatives, false_positives

    def score(self) -> None:

        true_positives = 0
        false_negatives = 0
        true_negatives = 0
        false_positives = 0

        percentage = "{0:." + str(self.precision) + "f}%"

        for attack_type in self.attack_types:
            tp, fn = self.__true_positives_false_negatives(attack_type)
            tn, fp = self.__true_negatives_false_positives(attack_type)
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
            print("Efficacy", percentage.format(balanced_accuracy * 100))
        
        print("------------- WAF Efficacy -------------" )
        sensitivity = true_positives / (true_positives + false_negatives)
        specificity = true_negatives / (true_negatives + false_positives)
        balanced_accuracy = (sensitivity + specificity) / 2
        print(percentage.format(balanced_accuracy * 100))


def main() -> None:
    parser = argparse.ArgumentParser(prog='score')
    parser.add_argument('-f', '--filename', dest='filename', required=True, help='filename of json formatted waf efficacy results', type=str)
    parser.add_argument('-a', '--attack-types', dest='attack_types', required=False, help='list of one or more attack types', nargs='+', type=str)
    parser.add_argument('-r', '--waf-response', dest='waf_response', required=False, help='HTTP status code the WAF uses for blocking requests', type=str)
    parser.add_argument('-k', '--precision', dest='precision', required=False, default=1, help='number of decimal places in percentages', type=int)
    args = parser.parse_args()
    
    waf_efficacy = WAFEfficacy(args.filename, args.waf_response, args.attack_types, args.precision)
    waf_efficacy.score()

if __name__ == '__main__':
    sys.exit(main())
