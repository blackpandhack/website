# config valid only for current version of Capistrano
lock "3.8.0"

set :application, "website"
set :repo_url, "ssh://github.com/blackpandhack/website.git"

set :ssh_options, keys: ["config/deploy_id_rsa"] if File.exist?("config/deploy_id_rsa")

set :nvm_node, 'v7.5.0'
set :nvm_map_bins, %w{bower npm}

set :deploy_to, "/var/www"

set :format, :pretty
namespace :deploy do
  task :setup_jekyll do
    on roles(:app) do
      within "#{deploy_to}/current" do
        execute :gem, "install bundler --conservative"
        execute :bundle, "update"

        execute :npm, "install -g bower"
        execute :bower, "install"

      	execute :jekyll, "build"
      end
    end
  end
end

after "deploy:symlink:release", "deploy:setup_jekyll"
