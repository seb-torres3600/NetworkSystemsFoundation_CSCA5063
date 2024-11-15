# Task: Create some functions for a simplified BGP router
#   Specifically, the withdraw, update, and next_hop functions of the Router
#   The class Route will be used.
# 
#   withdraw(rt) - rt is type Route. If a simplified BGP router gets this message, it will   
#


class Route:
    # A prefix is in form 
    neighbor = ""  # The router that send this router - will be a.b.c.d
    prefix = ""    # The IP address portion of a prefix - will be a.b.c.d
    prefix_len = 0 # The length portion of a prefix - will be an integer
    path = []      # the AS path - list of integers

    def __init__(self, neigh, p, plen, path):
        self.neighbor = neigh
        self.prefix = p
        self.prefix_len = plen
        self.path = path 

    # convert Route to a String    
    def __str__(self):
        return self.prefix+"/"+str(self.prefix_len)+"- ASPATH: " + str(self.path)+", neigh: "+self.neighbor

    # Get the prefix in the a.b.c.d/x format
    def pfx_str(self):
        return self.prefix+"/"+str(self.prefix_len)


# Implement the following functions:
#  update - the router received a route advertisement (which can be a new one, or an update
#         - the function needs to store the route in the RIB
#  withdraw - the router received a route withdraw message
#          - the function needs to delete the route in the RIB
#  nexthop - given ipaddr in a.b.c.d format as a string (e.g., "10.1.2.3"), perform a longest prefix match in the RIB
#          - Select the best route among multiple routes for that prefix by path length.  
#          - if same length, return either

class Router:
    # You can use a different data structure
    # dictionary with key of the prefix, value a list of Route
    # example: rib["10.0.0.0/24"] = [Route("1.1.1.1", "10.0.0.0", 24, [1,2,3]), 
    #                                Route("2.2.2.2", "10.0.0.0", 24, [10,20])]
    #          rib["10.0.0.0/22"] = [Route("3.3.3.3", "10.0.0.0", 22, [33,44,55,66]]
    rib = {} 

    # If you use the same data structure for the rib, this will print it
    def printRIB(self):
        for pfx in self.rib.keys():
            for route in self.rib[pfx].keys():
                print(f"{pfx} - {route} - {self.rib[pfx][route]}") 


    # TASK
    def update(self, rt):
        # Get formatted prefix from route
        prefix = rt.pfx_str()
        # If we already have routes for this prefix
        if prefix in self.rib.keys():
            # If neighbor key exists, update the neighbor
            if rt.neighbor in self.rib[prefix].keys():
                print(f"Updating path to {rt.path} for {prefix} with neighbor {rt.neighbor}")
                self.rib[prefix][rt.neighbor] = rt.path
                return
            else:
                # If key doesn't exist add neighbor and path to prefix dict
                print(f"Updating new neighbor {rt.neighbor} and new path {rt.path} for {prefix}")
                self.rib[prefix].update({rt.neighbor: rt.path})
                return
        # If prefix doesn't exist, add it with newneighbor and key
        print(f"Adding new prefix {prefix} with neighbor {rt.neighbor} and path {rt.path}")
        self.rib[prefix] = {rt.neighbor: rt.path}

    # TASK    
    def withdraw(self, rt):
        prefix = rt.pfx_str()
        # if prefix exist in our rib
        if prefix in self.rib.keys():
            # if neighbor exists in that prefix dict, delete it
            if rt.neighbor in self.rib[prefix].keys():
                print(f"Removing {prefix} - {rt.neighbor}")
                del self.rib[prefix][rt.neighbor]
                # If prefix dict is now empty, delete the prefix too
                if not self.rib[prefix]:
                    print(f"Prefix {prefix} is now empty, deleting")
                    del self.rib[prefix]
                return
        print(f"Route {prefix} - {rt.neighbor} was not found to remove")
        return 
    
    def convertToBinaryString(self, ip):
        vals = ip.split(".")
        a = format(int(vals[0]), 'b').rjust(8, '0')
        b = format(int(vals[1]), 'b').rjust(8, '0')
        c = format(int(vals[2]), 'b').rjust(8, '0')
        d = format(int(vals[3]), 'b').rjust(8, '0')
        return a+b+c+d



    # ipaddr in a.b.c.d format
    # find longest prefix that matches
    # then find shortest path of routes for that prefix
    def next_hop(self, ipaddr):
        retval = None
        longest_matching_prefix = None
        binary_ip = self.convertToBinaryString(ipaddr)

        # Use set of rib prefixes to avoid duplicates
        for prefix in set(self.rib.keys()):
            # Grab the number of bits that need to match from prefix
            matching_bits = int(prefix.split("/")[1])
            binary_prefix = self.convertToBinaryString(prefix.split("/")[0])
            # if the approriate number of bits match
            if binary_ip[:matching_bits] == binary_prefix[:matching_bits]:
                # if we already have a prefix, and we have a longer prefix, update the longest prefix
                if longest_matching_prefix:
                    if matching_bits > int(longest_matching_prefix.split("/")[1]):
                        longest_matching_prefix = prefix
                else:
                    longest_matching_prefix = prefix

        # if we ended up with no prefix, return early with None
        if not longest_matching_prefix:
            print(f"No prefix matches for given ip - {ipaddr}")
            return retval

        shortest_path = None
        # Go through neighbors of our longest prefix
        for neigh in self.rib[longest_matching_prefix].keys():
            # if we have a shortest path, swap with new path if it's shorter
            if shortest_path:
                if len(self.rib[longest_matching_prefix][neigh]) < len(shortest_path):
                    shortest_path = self.rib[longest_matching_prefix][neigh]
                    retval = neigh
            else:
                shortest_path = self.rib[longest_matching_prefix][neigh]
                retval = neigh
        print(f"Next hop found for {ipaddr}: Prefix {longest_matching_prefix} and shortest path {retval}")
        return retval



def test_cases():
    rtr = Router()

    #Test that withdrawing a non-existant route works
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    #Test updates work - same prefix, two neighbors
    rtr.update (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))
    rtr.update (Route("2.2.2.2", "10.0.0.0", 24, [1,2]))


    #Test updates work - overwriting an existing route from a neighbor
    rtr.update (Route("2.2.2.2", "10.0.0.0", 24, [1, 22, 33, 44]))

    # print("RIB")
    # rtr.printRIB()

    #Test updates work - an overlapping prefix (this case, a shorter prefix)
    rtr.update (Route("2.2.2.2", "10.0.0.0", 22, [4,5,7,8]))

    #Test updates work - completely different prefix
    rtr.update (Route("2.2.2.2", "12.0.0.0", 16, [4,5]))
    rtr.update (Route("1.1.1.1", "12.0.0.0", 16, [1, 2, 30]))

    # print("RIB")
    # rtr.printRIB()

    # Should not return an ip
    nh = rtr.next_hop("10.2.0.13")
    assert nh == None

    # Should return an ip
    nh = rtr.next_hop("10.0.0.13")
    assert nh == "1.1.1.1"

    # Test withdraw - withdraw the route from 1.1.1.1 that we just matched
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    # Should match something different
    nh = rtr.next_hop("10.0.0.13")
    assert nh == "2.2.2.2"

    # Re-announce - so, 1.1.1.1 would now be best route
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    
    rtr.update (Route("2.2.2.2", "10.0.0.0", 22, [4,5,7,8]))
    # Should match 10.0.0.0/22 (next hop 2.2.2.2) but not 10.0.0.0/24 (next hop 1.1.1.1)
    nh = rtr.next_hop("10.0.1.77")
    assert nh == "2.2.2.2"

    # Test a different prefix
    nh = rtr.next_hop("12.0.12.0")
    assert nh == "2.2.2.2"

    rtr.update (Route("1.1.1.1", "20.0.0.0", 16, [4,5,7,8]))
    rtr.update (Route("2.2.2.2", "20.0.0.0", 16, [44,55]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "2.2.2.2"

    rtr.update (Route("1.1.1.1", "20.0.12.0", 24, [44,55,66,77,88]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "1.1.1.1"

    # Remember to delete the entry from the RIB, not just removing the specific route
    # That is, when you withdraw, remove the route for the prefix, and if there are 0 routes, remove the prefix from the RIB
    rtr.withdraw(Route("1.1.1.1", "20.0.12.0", 24, [44,55,66,77,88]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "2.2.2.2"








if __name__ == "__main__":
    test_cases()
    

