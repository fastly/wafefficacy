import json
import sys
import argparse
from typing import List, Tuple

class WAFEfficacy:
    """
    Calculates WAF Efficacy Score
    """
    def __init__(self, filename: str, waf_response: str = "406 Not Acceptable", 
                 attack_types: List[str] = ['cmdexe', 'sqli', 'traversal', 'xss'], precision: int = 1, outfile: str = None) -> None:
        with open(filename, 'r') as f:
            self.results = [json.loads(line) for line in f]
        self.attack_types = attack_types
        self.waf_response = waf_response
        self.percentage = "{0:." + f"{precision}" + "f}%"
        self.efficacy_scores = {}
        self.outfile = outfile
    
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
            efficacy_score = balanced_accuracy * 100
            self.efficacy_scores[attack_type] = efficacy_score
            print("Efficacy", self.percentage.format(efficacy_score))
        
        print("------------- WAF Efficacy -------------" )
        sensitivity = true_positives / (true_positives + false_negatives)
        specificity = true_negatives / (true_negatives + false_positives)
        balanced_accuracy = (sensitivity + specificity) / 2
        efficacy_score = balanced_accuracy * 100
        self.efficacy_scores[attack_type] = efficacy_score
        self.efficacy_scores['overall'] = efficacy_score
        print(self.percentage.format(efficacy_score))
        
        if self.outfile:
            with open(self.outfile, 'w') as fp:
                json.dump(self.efficacy_scores, fp)
                fp.write("\n")
    
    def efficacy_assertions(self, file: str = "") -> None:
        if file:
            failed = False
            with open(file, 'r') as fp:
                assertions = json.load(fp)
                for attack_type, want in assertions.items():
                    # avoid exact comparisons on floats, they're potentially flaky
                    epsilon = 0.0000001
                    got = self.efficacy_scores[attack_type]
                    if got < want - epsilon:
                        failed = True
                        print("FAIL: wafefficacy_%s: want >= %f, got %f" % (attack_type, want, got))
            if failed:
                sys.exit(1)
            print("PASS: wafefficacy")


def main() -> None:
    parser = argparse.ArgumentParser(prog='score')
    parser.add_argument('-a', '--attack-types', dest='attack_types', required=False, help='list of one or more attack types', nargs='+', type=str, default=['cmdexe', 'sqli', 'traversal', 'xss'])
    parser.add_argument('-f', '--filename', dest='filename', required=True, help='filename of json formatted waf efficacy results', type=str)
    parser.add_argument('-i', '--input-assertions', dest='assertions', required=False, help='input json file with efficacy assertions for each attack type', type=str, default="")
    parser.add_argument('-k', '--precision', dest='precision', required=False, help='number of decimal places in percentages', type=int, default=1)
    parser.add_argument('-o', '--output', dest='outfile', required=False, help='output json file with efficacy scores', type=str)
    parser.add_argument('-r', '--waf-response', dest='waf_response', required=False, help='HTTP status code the WAF uses for blocking requests', type=str, default="406 Not Acceptable")
    args = parser.parse_args()
    
    waf_efficacy = WAFEfficacy(args.filename, args.waf_response, args.attack_types, args.precision, args.outfile)
    waf_efficacy.score()
    waf_efficacy.efficacy_assertions(args.assertions)

if __name__ == '__main__':
    sys.exit(main())
