import sys
import argparse
from datetime import datetime
"""Program to generate custom password lists"""

# Suffix configuration
BASE_SPECIALS = ["!", "@", "#", "$"]
TRAILING_1 = ["1"]  # Only added to bare words, not after years/sequences

def score_password(password, company, city, current_year):
    """Score a password by likelihood of being used (higher = more likely)"""
    score = 0
    pw_lower = password.lower()
    
    # High-value base words
    if pw_lower.startswith("password"):
        score += 100
    if company and pw_lower.startswith(company.lower()):
        score += 80
    
    # Season words are very common
    seasons = ["spring", "summer", "winter", "fall", "autumn"]
    for season in seasons:
        if pw_lower.startswith(season):
            score += 70
            break
    
    # City is moderately common
    if city and pw_lower.startswith(city.lower()):
        score += 50
    
    # @ symbol is a common substitution
    if "@" in password:
        score += 25
    
    # Recent years are more likely
    for year in range(current_year - 1, current_year + 2):
        if str(year) in password:
            score += 30
            break
        if str(year)[2:] in password:  # Short year like "24"
            score += 20
            break
    
    # Simple suffixes are most common
    if password.endswith("1"):
        score += 40
    elif password.endswith("!"):
        score += 35
    elif password.endswith("123"):
        score += 30
    elif password.endswith("123!"):
        score += 28
    
    # Penalize longer/complex suffixes
    if password.endswith("1234567"):
        score -= 10
    
    # Common one-offs get a boost
    common_oneoffs = ["Password1", "P@ssw0rd"]
    if password in common_oneoffs:
        score += 50
    
    # Proper capitalization is more common
    if password[0].isupper() and password[1:].islower() == False:
        score += 5
    if password[0].isupper():
        score += 10
        
    # Shorter passwords slightly more common
    if len(password) <= 10:
        score += 5
    
    return score


def add_variants(results, base, suffixes):
    """Add base word with all suffix combinations"""
    results.add(base)
    for suffix in suffixes:
        results.add(f"{base}{suffix}")


def create_password_list(company, include_seasons=True, base_year=None, year_range=2, city=None):
    if base_year is None:
        base_year = datetime.now().year - 1
    
    current_year = datetime.now().year
    
    one_offs = ["welcome", "letmein", "Password", "P@ssw0rd"]
    season_words = ["spring", "summer", "winter", "fall", "autumn"]
    results = set()
    
    words = ["password", company.lower(), company.capitalize()]
    
    if include_seasons:
        words += season_words
    
    if city:
        words += [city, city.lower(), city.capitalize()]
    
    results.update(one_offs)
    
    for word in words:
        variants = [word, word.lower(), word.capitalize()]
        
        for variant in variants:
            # Bare word + specials (including "1" here)
            add_variants(results, variant, BASE_SPECIALS + TRAILING_1)
            
            # Year-based combinations (no trailing "1")
            for year in range(base_year, base_year + year_range + 1):
                for yr in [str(year), str(year)[2:]]:
                    add_variants(results, f"{variant}{yr}", BASE_SPECIALS)
                    add_variants(results, f"{variant}@{yr}", BASE_SPECIALS)
            
            # Number sequences (no trailing "1")
            numbers = ""
            for k in range(1, 8):
                numbers += str(k)
                if len(numbers) >= 3:
                    add_variants(results, f"{variant}{numbers}", BASE_SPECIALS)
                    add_variants(results, f"{variant}@{numbers}", BASE_SPECIALS)
    
    sorted_results = sorted(
        results,
        key=lambda p: (-score_password(p, company, city, current_year), p)
    )
    
    return sorted_results


def main():
    parser = argparse.ArgumentParser(description="Generate custom password lists")
    parser.add_argument("company", help="Company name to include in passwords")
    parser.add_argument("-c", "--city", help="City name to include")
    parser.add_argument("-y", "--year", type=int, default=None, 
                        help=f"Base year (default: {datetime.now().year - 1})")
    parser.add_argument("-r", "--range", type=int, default=2, dest="year_range",
                        help="Year range to generate (default: 2)")
    parser.add_argument("--no-seasons", action="store_true", 
                        help="Exclude season words")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    passwords = create_password_list(
        company=args.company,
        include_seasons=not args.no_seasons,
        base_year=args.year,
        year_range=args.year_range,
        city=args.city
    )
    
    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(passwords))
        print(f"Generated {len(passwords)} passwords to {args.output}")
    else:
        for password in passwords:
            print(password)


if __name__ == "__main__":
    main()