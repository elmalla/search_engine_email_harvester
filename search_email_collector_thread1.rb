##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
#The script modfied to seach any email for any keyword - 
#Thread 1 - searching verfied emails/urls from the email_master table
#Thread 2 - searching verfied emails/urls from the email_master table
#Thread 3 - searching company names
#Thread 4 - searching words like automation, IT,egypt, india 
#Thread 5 - searching telephones, and urls, country, address
##

require 'msf/core'
require 'net/http'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Search Engine Domain Email Address Collector',
      'Description' => %q{
          This module uses Google, Bing and Yahoo and Ask and Aol to create a list of
        valid email addresses for the target domain.
      },
      'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'License' => MSF_LICENSE))

     register_options(
      [
        OptString.new('DOMAIN', [ false, "The domain name to locate email addresses for"]),
        OptBool.new('SEARCH_GOOGLE', [ true, 'Enable Google as a backend search engine', true]),
        OptBool.new('SEARCH_BING', [ false, 'Enable Bing as a backend search engine', false]),
        OptBool.new('SEARCH_YAHOO', [ true, 'Enable Yahoo! as a backend search engine', true]),
	    OptBool.new('SEARCH_ASK', [ true, 'Enable Ask as a backend search engine', true]),
	    OptBool.new('SEARCH_AOL', [ true, 'Enable Aol as a backend search engine', true]),
        OptBool.new('SEARCH_YANDEX', [false, 'Enable Yandex as a backend search engine', false]),
        OptBool.new('SEARCH_BAIDU', [true, 'Enable Baidu as a backend search engine', true]),
        OptBool.new('SEARCH_LYCOS', [false, 'Enable Lycos as a backend search engine', false]),
        OptString.new('EOUTFILE', [ false, "A filename to store the generated email list"]),
        OptString.new('GOUTFILE', [ false, "A filename to store the generated Google result"]),

      ], self.class)

    register_advanced_options(
      [
        OptString.new('PROXY', [ false, "Proxy server to route connection. <host>:<port>",nil]),
        OptString.new('PROXY_USER', [ false, "Proxy Server User",nil]),
        OptString.new('PROXY_PASS', [ false, "Proxy Server Password",nil])
      ], self.class)

  end
    
    
  #Search google.com for email's of target domain
  def search_google(targetdom)
    print_status("Searching Google for email addresses from #{targetdom}")
    grawresponse = ""
    gsubresponse = ""
    gfile = ""
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.google.com")
    searches = ["100", "200","300", "400", "500", "600", "700", "800", "900", "1000"]
    searches.each { |num|
      resp = clnt.get2("/search?hl=en&lr=&ie=UTF-8&q=%40"+targetdom+"&start=#{num}&sa=N&filter=0&num=100",header)
      response << resp.body
      grawresponse << resp.body
    }
    print_status("Extracting emails from Google search results...")
    response.gsub!(/<.?em?[>]*>/, "")
    gsubresponse << response
    #print_status("Removing tags from Google search results...#{response}")
    response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
      print_status("Found Emails Google search results...#{t}") 
      emails << t
    end
    gfile = File.join("/home", "email_collect_data","g_reply_#{targetdom}.txt")
    #print_status("File name for Google search results...#{gfile}")
    write_output(gsubresponse,gfile)
    print_status("Extracting emails from Google search results...#{emails.length}")
    return emails.uniq
  end



  #Search Yahoo.com for email's of target domain
  def search_yahoo(targetdom)
   begin
    print_status("Searching Yahoo for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("search.yahoo.com")
    searches = ["1", "101","201", "301", "401", "501", "601", "701", "801", "901", "1001"]
    searches.each { |num|
      resp = clnt.get2("/search?p=%40#{targetdom}&n=100&ei=UTF-8&va_vt=any&vo_vt=any&ve_vt=any&vp_vt=any&vd=all&vst=0&vf=all&vm=p&fl=0&fr=yfp-t-152&xargs=0&pstart=1&b=#{num}",header)
      response << resp.body

    }
    print_status("Extracting emails from Yahoo search results...")
    response.gsub!(/<.?b?[>]*>/, "")
    #response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t.downcase
    end     
   rescue  
     print_status("Searching Yahoo Error #{targetdom}")
     #print_status("Searching Yahoo Error #{e.backtrace.inspect}")
   end
  ensure
    print_status("Extracting emails from Yahoo search results...#{emails.length}") 
    if !emails.empty? 
      return emails.uniq
    else
      return ""
    end 
  end

  #Search Bing.com for email's of target domain
  def search_bing(targetdom)
  begin
    print_status("Searching Bing email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.bing.com")
    searches = 1
    while searches < 1001
      begin
        resp = clnt.get2("/search?q=%40#{targetdom}&first=#{searches.to_s}",header)
        response << resp.body
      rescue
      end
      searches = searches + 10
    end
    print_status("Extracting emails from Bing search results...")
    response.gsub!(/<.?strong?[>]*>/, "")
    
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t.downcase
    end
    
   rescue 
     print_status("Searching Bing Error #{targetdom}")
     
   end 
   ensure
    print_status("Extracting emails from Bing search results...#{emails.length}")
    if !emails.empty?  
      return emails.uniq
    else
      return ""
    end 
  end

  #Search ask.com for email's of target domain
  def search_ask(targetdom)
  begin
    print_status("Searching Ask for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.ask.com")
    searches = ["1", "2","3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19","20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"]
    searches.each { |num|
      resp = clnt.get2("/web?q=%40#{targetdom}&page=#{num}&qsrc=0&o=0&l=dir",header)
      response << resp.body
    }
    print_status("Extracting emails from Ask search results...")
    response.gsub!(/<.?em?[>]*>/, "")
    #response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t
    end
    
   rescue 
     print_status("Searching Ask Error #{targetdom}")
     
   end
   ensure
    print_status("Extracting emails from Ask search results...#{emails.length}") 
    if !emails.empty?   
      return emails.uniq
    else
      return ""
    end  
  end

  #Search aol.com for email's of target domain
  def search_aol(targetdom)
  begin
    print_status("Searching Aol for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("search.aol.com")
    searches = ["1", "2","3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19","20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"]
    searches.each { |num|
      resp = clnt.get2("/aol/search?enabled_terms=&q=%40#{targetdom}&page=#{num}",header)
      response << resp.body
    }
    print_status("Extracting emails from Aol search results...")
    response.gsub!(/<.?b?[>]*>/, "")
    #response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t
    end
    #return emails.uniq
   rescue 
     print_status("Searching Aol Error #{targetdom}")
     #print_status("Searching Yandex Error #{e.backtrace.inspect}")
   end
   ensure
    print_status("Extracting emails from Aol search results...#{emails.length}")
    if !emails.empty?
      return emails.uniq
    else
      return ""
    end  
  end  
  
  # Search yandex.ru for email's of target domain
  def search_yandex(targetdom)
  begin
    print_status("Searching Yandex for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.yandex.ru")
    searches = ["1", "2","3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19","20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"]
    searches.each { |num|
      resp = clnt.get2("/yandsearch?p=#{num}&lr=105070&text=%40#{targetdom}",header)
      response << resp.body
    }
    print_status("Extracting emails from Yandex search results...")
    response.gsub!(/<.?b?[>]*>/, "")
    #response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t
    end
    #return emails.uniq
   rescue 
     print_status("Searching Yandex Error #{targetdom}")
    
   end
   ensure
    print_status("Extracting emails from yandex search results...#{emails.length}") 
    if !emails.empty?
      return emails.uniq
    else
      return ""
    end  
  end  
  
  # Search baidu.com for email's of target domain
   def search_baidu(targetdom)
   begin
    print_status("Searching Baidu for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.baidu.com")
    searches = ["1", "2","3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19","20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"]
    searches.each { |num|
      resp = clnt.get2("/s?wd=%40#{targetdom}&pn=#{num}&ie=utf-8&usm=1",header)
      response << resp.body
    }
    print_status("Extracting emails from Baidu search results...")
    response.gsub!(/<.?em?[>]*>/, "")
    
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t
    end
    
   rescue 
     print_status("Searching baidu Error #{targetdom}")
     
   end
   ensure
    print_status("Extracting emails from baidu search results...#{emails.length}")
    if !emails.empty?      
      return emails.uniq
    else
      return ""
    end  
  end 
  
  # Search lycos.com for email's of tardet domain
  def search_lycos(targetdom)
  begin
    print_status("Searching Lycos for email addresses from #{targetdom}")
    response = ""
    emails = []
    header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.lycos.com")
    searches = ["1", "2","3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19","20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"]
    searches.each { |num|
      resp = clnt.get2("web?q=%40#{targetdom}&keyvol=00defd123337e0f7d5f1&pn=#{num}",header)
      response << resp.body
    }
    print_status("Extracting emails from Lycos search results...")
    response.gsub!(/<.?em?[>]*>/, "")
    
    response.scan(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i) do |t|
      emails << t
    end
    
   rescue 
     print_status("Searching lycos Error #{targetdom}")
     
   end
   ensure
    print_status("Extracting emails from lycos search results...#{emails.length}")
    if !emails.empty?
      return emails.uniq
    else
      return ""
    end  
  end 
  
  #for saving  all emails found into a file
  def write_output(data,file)
    print_status("Writing email address list to #{file}...")
    ::File.open(file, "ab") do |fd|
      fd.puts(data)
    end
  end

  def run
    if datastore['PROXY']
      @proxysrv,@proxyport = datastore['PROXY'].split(":")
      @proxyuser = datastore['PROXY_USER']
      @proxypass = datastore['PROXY_PASS']
    else
      @proxysrv,@proxyport = nil, nil
    end
    print_status("Harvesting emails .....")

   #Call openvpn command
   def bash(command)
    escaped_command = Shellwords.escape(command)
    system "bash -c #{escaped_command}"
   end
   
   
   def my_first_private_ipv4
    Socket.ip_address_list.detect{|intf| intf.ipv4_private?}
   end

   def my_first_public_ipv4
  Socket.ip_address_list.detect{|intf| intf.ipv4? and !intf.ipv4_loopback? and !   intf.ipv4_multicast? and !intf.ipv4_private?}
   end

   def time_diff_milli(start, finish)
   (finish - start) /60
   end

   #Mointor my real IP before VPN is started and sleep if the VPN isn't connected yet 
   # It isn't the best way but it was hard to syn the VPN IP schedular with the Ruby script  
   def use_vpn_connection     
       begin
        remote_ip_start = open('http://whatismyip.akamai.com').read
        print_status("My Public IP at start #{remote_ip_start}")
        
        if !remote_ip_start.empty?
          f_subnet = remote_ip_start.partition('.').first
        end
        sleep (2)
        
       end while f_subnet == '218'|| f_subnet == '203'|| f_subnet == '62'|| f_subnet == '95'
    end
    
   #for domains ex. smartrac.com and search engines for asscociated emails 
   def read_input(file)
    urls=[]
    print_status("Reading file from #{file}...")   
    f = File.open(file, "r")
    f.each_line do |line|
       urls.push(line)
       
    end    
    f.close
    
    return urls
  end
    
  #get unique elemenst from arrays
  def diff a, b
    a = a.sort
    b = b.sort
    result = []
    bi = 0
    ai = 0
   while (ai < a.size && bi < b.size)
    if a[ai] == b[bi]
      ai += 1
      bi += 1
    elsif a[ai]<b[bi]
      result << a[ai]
      ai += 1
    else
      result << b[bi]
      bi += 1
    end
   end
    result += a[ai, a.size-ai] if ai<a.size
    result += b[bi, b.size-bi] if bi<b.size
    result
  end
    
    # Folder can be changed 
    datastore['EMAIL_FILE']="/home/emails_harvested_main.txt"
    datastore['EMAIL_FILE1']="/home/email_collect_data_thread1/emails.txt"
    

    datastore['GOUTFILE']="/home/email_collect_data_thread1/googlereply.txt"
    
   
    datastore['URL_FILE']="/home/email_collect_data_thread1/verfied_urls_20160904.txt"
    
	#Searched emails
    datastore['SEARCHED_FILE']="/home/url_searched_main.txt"
    datastore['SEARCHED_FILE1']="/home/email_collect_data_thread1/url_searched.txt"  
    
    remaining_urls_count = 0
    
    emails_harvested_count = 0
    remote_ip_start =''
    remote_ip_finish =''
    searched_emails1=[]
    searched_emails2=[]
    target_urls =[]
    searched_urls1 =[]
    searched_urls2 =[]
   
    remaining_urls =[]
    
    
  
    target_urls = read_input(datastore['URL_FILE'])
    
    target_urls.map!{|element| element.to_s.downcase}
    target_urls.map!{|element| element.gsub(/\s+/, "")}
    target_urls.map!{|element| element.gsub("\n","")}     
    target_urls.flatten!
    target_urls.uniq!
    target_urls.sort!

    searched_emails1 = read_input(datastore['EMAIL_FILE'])
    
    print_status("Searched emails  count.... #{searched_emails1.length}")
    
	searched_emails1.map!{|element| element.split("@").last}
    searched_emails1.map!{|element| element.to_s.downcase}
    searched_emails1.map!{|element| element.gsub(/\s+/, "")}
    searched_emails1.map!{|element| element.gsub("\n","")}
    searched_emails1.flatten!
    searched_emails1.uniq!
    searched_emails1.sort!

    
    searched_urls1 = read_input(datastore['SEARCHED_FILE'])  
    #searched_urls = ["ogdcl.com","zakhem.co.uk"]
    searched_urls1.map!{|element| element.to_s.downcase}
    searched_urls1.map!{|element| element.gsub(/\s+/, "")}    
    searched_urls1.map!{|element| element.gsub("\n","")}
    searched_urls1.flatten!
    searched_urls1.uniq!
    searched_urls1.sort!

    
    print_status("Searched Urls  count.... #{searched_urls1.length}")
    print_status("Searched Urls 2 count.... #{searched_urls2.length}")
    
	
    print_status("Searched emails  count.... #{searched_emails1.length}")
    print_status("Searched emails 2 count.... #{searched_emails2.length}")
    
    print_status("Target Urls count.... #{target_urls.length}")
    
    remaining_urls = (target_urls - searched_emails1) 
    print_status("remaining_urls count.... #{remaining_urls.length}")

    
    remaining_urls = (remaining_urls - searched_urls1)
    print_status("remaining_urls count.... #{remaining_urls.length }")  

    remaining_urls.map!{|element| element.gsub("\r","")}

    remaining_urls_count = remaining_urls.length
 
    if !remaining_urls.empty?
       print_status("Searching our own URLs from #{datastore['URL_FILE']}")
     
     remaining_urls.each do |target|
      
       emails = []
       searched = []
       t1 = Time.now
       remote_ip_start = open('http://whatismyip.akamai.com').read
       use_vpn_connection
       
	   
       emails << search_baidu(target) if datastore['SEARCH_BAIDU']
       t2 = Time.now
       print_status("Located emails in:#{time_diff_milli t1, t2} m")
       
       use_vpn_connection
       t2 = Time.now
       emails << search_yandex(target) if datastore['SEARCH_YANDEX']
       t3 = Time.now
       print_status("Located emails in:#{time_diff_milli t2, t3} m")

       use_vpn_connection
       t3 = Time.now
       emails << search_aol(target) if datastore['SEARCH_AOL']
       t4 = Time.now
       print_status("Located emails in:#{time_diff_milli t3, t4} m")

       use_vpn_connection
       t4 = Time.now
       emails << search_ask(target) if datastore['SEARCH_ASK']
       t5 = Time.now
       print_status("Located emails in:#{time_diff_milli t4, t5} m")

       use_vpn_connection
       t5 = Time.now
       emails << search_yahoo(target) if datastore['SEARCH_YAHOO']
       t6 = Time.now
       print_status("Located emails in:#{time_diff_milli t5, t6} m")
       use_vpn_connection

       t6 = Time.now
       emails << search_bing(target) if datastore['SEARCH_BING']
       t7 = Time.now
       print_status("Located emails in:#{time_diff_milli t6, t7} m")
       searched << target
       searched.flatten!
       
       remote_ip_finish = open('http://whatismyip.akamai.com').read
       print_status("My Public IP at start #{remote_ip_start} ....at end #{remote_ip_finish}")
       
       emails.flatten!
       emails.uniq!
       emails.sort!
       
       t8 = Time.now
       print_status("Located #{emails.length} email add.for #{target} in:#{time_diff_milli t1, t8} m")
     
       emails.each do |e|
         print_status("\t#{e.to_s}")
       end

       remaining_urls_count   -= 1
       emails_harvested_count += emails.length
       searched_count          = remaining_urls.length - remaining_urls_count
      
       print_status("Remaining Urls #{remaining_urls_count}..searched #{searched_count}")
       write_output(emails.join("\n"),datastore['EMAIL_FILE1']) if datastore['EMAIL_FILE1']
      
       print_status("Add #{target}...to searched list")
       write_output(searched.join("\n"),datastore['SEARCHED_FILE1']) if datastore['SEARCHED_FILE1']
      
     end
   end 
     print_status("Finished searching located #{emails_harvested_count} emails") 

  end
end
