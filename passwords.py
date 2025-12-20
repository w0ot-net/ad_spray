import sys
import argparse
from datetime import datetime

"""Program to generate custom password lists"""

def create_password_list(company, include_seasons=True, base_year=None, year_range=2, city=None):
    # Auto-detect current year if not specified
    if base_year is None:
        base_year = datetime.now().year - 1  # Start from last year
    
    one_offs = ["welcome", "Welcome1", "letmein", , "Password", "P@ssw0rd"]
    season_words = ["spring", "summer", "winter", "fall", "autumn"]
    specials = ["!", "@", "#", "$", "123!", "1"]
    results = set()  # Use set to avoid duplicates
    
    words = ["password", company, company.lower(), company.upper()]
    
    if include_seasons:
        words += season_words
    
    if city:
        words += [city, city.lower(), city.capitalize()]
    
    # Add one-offs
    results.update(one_offs)
    
    for word in words:
        variants = [word, word.lower(), word.capitalize(), word.upper()]
        
        for variant in variants:
            results.add(variant)
            
            # Year-based combinations
            for year in range(base_year, base_year + year_range + 1):
                year_short = str(year)[2:]  # Last 2 digits
                
                for yr in [str(year), year_short]:
                    results.add(f"{variant}{yr}")
                    results.add(f"{variant}@{yr}")
                    
                    for special in specials:
                        results.add(f"{variant}{yr}{special}")
                        results.add(f"{variant}@{yr}{special}")
            
            # Number sequences
            numbers = ""
            for k in range(1, 8):
                numbers += str(k)
                if len(numbers) >= 3:
                    results.add(f"{variant}{numbers}")
                    results.add(f"{variant}@{numbers}")
                    
                    for special in specials:
                        results.add(f"{variant}{numbers}{special}")
                        results.add(f"{variant}@{numbers}{special}")
    
    return sorted(results)


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