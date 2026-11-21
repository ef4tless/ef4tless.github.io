#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'

# Fallback permalink generator for manually added posts that do not declare a
# custom `permalink` in front matter. Keeps Chinese titles from turning into
# long percent-encoded URLs.
Jekyll::Hooks.register :site, :post_read do |site|
  site.posts.docs.each do |post|
    permalink = post.data['permalink']
    next unless permalink.nil? || permalink.to_s.strip.empty? || permalink == '/posts/:title/'

    short_id = Digest::SHA1.hexdigest(post.relative_path)[0, 8]
    post.data['permalink'] = "/posts/id=#{short_id}/"
  end
end
