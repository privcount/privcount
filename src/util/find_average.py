import pprint

if __name__ == '__main__':
  results = {}
  epochs = 0 
  with open('results.txt','r') as f:
    for line in f:
      site, visits = line.strip().split(":")
      if site == 'Other':
        epochs = epochs + 1
      if site in results:
        results[site] = float(visits) + results[site]
      else:
       results[site] = float(visits)

  for key in results:
    results[key] = results[key]/epochs
#  pprint.pprint(results)
  print 'Epochs: ', epochs
  for site in sorted(results, key=results.get, reverse=True):
    print site, results[site]
